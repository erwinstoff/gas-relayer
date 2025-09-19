// src/index.ts - Updated Gas Relayer Backend for ERC2771Forwarder
import express from 'express';
import { ethers } from 'ethers';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://frontend-web3.vercel.app',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/metatx', limiter);

app.use(express.json({ limit: '1mb' }));

// Health check
app.get('/', (req, res) => {
  res.json({ 
    status: 'ERC2771Forwarder Gas Relayer Service is running',
    timestamp: new Date().toISOString()
  });
});

// Debug endpoint for testing forwarder contract
app.get('/debug/forwarder/:chainId/:userAddress', async (req, res) => {
  try {
    const { chainId, userAddress } = req.params;
    const CHAIN_CONFIG = getChainConfig();
    
    const chainIdNum = parseInt(chainId);
    if (!CHAIN_CONFIG[chainIdNum as keyof typeof CHAIN_CONFIG]) {
      return res.status(400).json({ error: 'Unsupported chain' });
    }
    
    const chainConfig = CHAIN_CONFIG[chainIdNum as keyof typeof CHAIN_CONFIG];
    const provider = await getWorkingProvider(chainIdNum);
    
    if (!RELAYER_PRIVATE_KEY) {
      return res.status(500).json({ error: 'Relayer private key not configured' });
    }
    
    const relayerWallet = new ethers.Wallet(RELAYER_PRIVATE_KEY, provider);
    
    if (!chainConfig.forwarderAddress) {
      return res.status(500).json({ error: 'Forwarder address not configured for this chain' });
    }
    
    const forwarderContract = new ethers.Contract(
      chainConfig.forwarderAddress,
      ERC2771_FORWARDER_ABI,
      relayerWallet
    );
    
    // Test basic contract calls
    const nonce = await forwarderContract.getNonce(userAddress);
    const relayerBalance = await provider.getBalance(relayerWallet.address);
    
    res.json({
      chainId,
      userAddress,
      forwarderAddress: chainConfig.forwarderAddress,
      nonce: nonce.toString(),
      relayerBalance: ethers.formatEther(relayerBalance),
      relayerAddress: relayerWallet.address
    });
  } catch (error: any) {
    res.status(500).json({
      error: 'Debug failed',
      message: error.message
    });
  }
});

// ERC2771Forwarder ABI
const ERC2771_FORWARDER_ABI = [
  "function execute((address from, address to, uint256 value, uint256 gas, uint256 nonce, uint48 deadline, bytes data) request, bytes signature) external payable returns (bool success, bytes returnData)",
  "function getNonce(address from) external view returns (uint256)",
  "function verify((address from, address to, uint256 value, uint256 gas, uint256 nonce, uint48 deadline, bytes data) request, bytes signature) external view returns (bool)"
];

// ERC20 ABI
const ERC20_ABI = [
  "function approve(address spender, uint256 amount) external returns (bool)",
  "function balanceOf(address owner) external view returns (uint256)",
  "function allowance(address owner, address spender) external view returns (uint256)"
];

// Chain configurations with ERC2771Forwarder addresses
const getChainConfig = () => ({
  1: {
    name: 'Ethereum Mainnet',
    rpcUrls: [
      process.env.ETH_RPC_URL || 'https://mainnet.infura.io/v3/8dce88ca5dbf449794bb96de804345c6',
    ],
    gasPrice: ethers.parseUnits('20', 'gwei'),
    maxGasLimit: 200000n,
    forwarderAddress: process.env.TRUSTED_FORWARDER_MAINNET
  },
  42161: {
    name: 'Arbitrum',
    rpcUrls: [
      process.env.ARB_RPC_URL || 'https://arb-mainnet.g.alchemy.com/v2/1NchczMp7D3slL3ERdF7kC-1i4oj3ByT',
    ],
    gasPrice: ethers.parseUnits('0.1', 'gwei'),
    maxGasLimit: 300000n,
    forwarderAddress: process.env.TRUSTED_FORWARDER_ARBITRUM
  },
  11155111: {
    name: 'Sepolia',
    rpcUrls: [
      process.env.SEPOLIA_RPC_URL || 'https://eth-sepolia.g.alchemy.com/v2/1NchczMp7D3slL3ERdF7kC-1i4oj3ByT',
    ],
    gasPrice: ethers.parseUnits('20', 'gwei'),
    maxGasLimit: 200000n,
    forwarderAddress: process.env.TRUSTED_FORWARDER_SEPOLIA
  }
});

// Supported tokens - ALL LOWERCASE for consistent comparison
const SUPPORTED_TOKENS: Record<number, string[]> = {
  1: [
    "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
    "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI
    "0x4fabb145d64652a948d72533023f6e7a623c7c53"  // BUSD
  ],
  42161: [
    "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", // USDT
    "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8", // USDC
    "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"  // DAI
  ],
  11155111: [
    "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238", // USDC
    "0x779877a7b0d9e8603169ddbd7836e478b4624789"  // LINK
  ]
};

const SPENDER_ADDRESS = process.env.SPENDER_ADDRESS;
const RELAYER_PRIVATE_KEY = process.env.RELAYER_PRIVATE_KEY;

if (!SPENDER_ADDRESS || !RELAYER_PRIVATE_KEY) {
  console.error('❌ Missing required environment variables:');
  console.error('- SPENDER_ADDRESS:', SPENDER_ADDRESS ? '✅ Set' : '❌ Missing');
  console.error('- RELAYER_PRIVATE_KEY:', RELAYER_PRIVATE_KEY ? '✅ Set' : '❌ Missing');
  process.exit(1);
}

// Get working provider with fallback RPCs
async function getWorkingProvider(chainId: number): Promise<ethers.JsonRpcProvider> {
  const config = getChainConfig()[chainId as keyof ReturnType<typeof getChainConfig>];
  if (!config) {
    throw new Error(`Unsupported chain: ${chainId}`);
  }

  for (const rpcUrl of config.rpcUrls) {
    try {
      console.log(`🔗 Trying RPC: ${rpcUrl.slice(0, 50)}...`);
      const provider = new ethers.JsonRpcProvider(rpcUrl, {
        name: config.name,
        chainId: chainId
      });
      
      // Test connection with timeout
      await Promise.race([
        provider.getBlockNumber(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000))
      ]);
      
      console.log(`✅ Connected to ${config.name}`);
      return provider;
      
    } catch (error: any) {
      console.log(`❌ RPC failed: ${error.message}`);
      continue;
    }
  }
  
  throw new Error(`All RPC endpoints failed for ${config.name}`);
}

// Validate EIP-712 signature for ERC2771Forwarder
function validateEIP712Signature(
  domain: any,
  types: any,
  message: any,
  signature: string,
  expectedSigner: string
): boolean {
  try {
    // Build the EIP-712 domain separator
    const domainSeparator = ethers.TypedDataEncoder.hashDomain(domain);
    
    // Build the struct hash
    const structHash = ethers.TypedDataEncoder.hash(domain, types, message);
    
    // Build the final hash
    const finalHash = ethers.keccak256(
      ethers.concat(['0x1901', domainSeparator, structHash])
    );
    
    // Recover the signer
    const recoveredAddress = ethers.recoverAddress(finalHash, signature);
    
    const isValid = recoveredAddress.toLowerCase() === expectedSigner.toLowerCase();
    
    console.log('🔍 EIP-712 Signature validation:', {
      expectedSigner: expectedSigner.toLowerCase(),
      recoveredAddress: recoveredAddress.toLowerCase(),
      isValid,
      domainName: domain.name,
      domainVersion: domain.version,
      domainChainId: domain.chainId,
      verifyingContract: domain.verifyingContract
    });
    
    return isValid;
  } catch (error) {
    console.error('❌ EIP-712 signature validation error:', error);
    return false;
  }
}

// Validate token - CASE INSENSITIVE
function isTokenSupported(chainId: number, tokenAddress: string): boolean {
  const supportedTokens = SUPPORTED_TOKENS[chainId];
  if (!supportedTokens) {
    console.log(`❌ Chain ${chainId} not supported`);
    return false;
  }
  
  const normalizedAddress = tokenAddress.toLowerCase();
  const isSupported = supportedTokens.includes(normalizedAddress);
  
  console.log(`🔍 Token validation:`, {
    chainId,
    originalAddress: tokenAddress,
    normalizedAddress,
    isSupported
  });
  
  if (!isSupported) {
    console.log(`❌ Token ${tokenAddress} not supported on chain ${chainId}`);
    console.log(`✅ Supported tokens:`, supportedTokens);
  }
  
  return isSupported;
}

// Main meta-transaction relay endpoint
app.post('/metatx', async (req, res) => {
  try {
    const {
      chainId,
      tokenAddress,
      userAddress,
      metaTxMessage
    } = req.body;

    console.log('📥 Received meta-transaction request:', {
      chainId,
      tokenAddress,
      userAddress: userAddress?.slice(0, 10) + '...',
      hasSignature: !!metaTxMessage?.signature
    });

    // Validate required fields with better error messages
    const missingFields = [];
    if (!chainId) missingFields.push('chainId');
    if (!tokenAddress) missingFields.push('tokenAddress');
    if (!userAddress) missingFields.push('userAddress');
    if (!metaTxMessage) missingFields.push('metaTxMessage');
    
    if (missingFields.length > 0) {
      console.log('❌ Missing required fields:', missingFields);
      console.log('📥 Received data:', { chainId, tokenAddress, userAddress, hasMetaTxMessage: !!metaTxMessage });
      return res.status(400).json({
        error: 'Missing required fields',
        missingFields,
        received: { chainId, tokenAddress, userAddress, hasMetaTxMessage: !!metaTxMessage }
      });
    }

    const { request, signature } = metaTxMessage;
    if (!request || !signature) {
      console.log('❌ Missing request or signature in metaTxMessage');
      return res.status(400).json({
        error: 'Missing request or signature in metaTxMessage'
      });
    }

    const CHAIN_CONFIG = getChainConfig();

    // Validate chain support
    if (!CHAIN_CONFIG[chainId as keyof typeof CHAIN_CONFIG]) {
      console.log('❌ Unsupported chain:', chainId);
      return res.status(400).json({
        error: 'Unsupported chain',
        supportedChains: Object.keys(CHAIN_CONFIG),
        receivedChain: chainId
      });
    }

    const chainConfig = CHAIN_CONFIG[chainId as keyof typeof CHAIN_CONFIG];
    
    // Check if forwarder is configured for this chain
    if (!chainConfig.forwarderAddress) {
      console.log('❌ No ERC2771Forwarder configured for chain:', chainId);
      return res.status(400).json({
        error: 'ERC2771Forwarder not configured for this chain',
        chainId,
        chainName: chainConfig.name
      });
    }

    // Validate token support
    if (!isTokenSupported(chainId, tokenAddress)) {
      console.log('❌ Unsupported token:', tokenAddress, 'on chain:', chainId);
      return res.status(400).json({
        error: 'Unsupported token address',
        supportedTokens: SUPPORTED_TOKENS[chainId] || [],
        receivedToken: tokenAddress.toLowerCase(),
        chainId: chainId
      });
    }

    // Validate ForwardRequest structure
    const requiredFields = ['from', 'to', 'value', 'gas', 'nonce', 'deadline', 'data'];
    const missingRequestFields = requiredFields.filter(field => request[field] === undefined);
    if (missingRequestFields.length > 0) {
      console.log('❌ Missing ForwardRequest fields:', missingRequestFields);
      return res.status(400).json({
        error: 'Invalid ForwardRequest structure',
        missingFields: missingRequestFields
      });
    }

    // Check deadline
    const now = Math.floor(Date.now() / 1000);
    const deadline = parseInt(request.deadline);
    if (now > deadline) {
      console.log('❌ Request expired');
      return res.status(400).json({
        error: 'Request expired. Please refresh and try again.'
      });
    }

    console.log('✅ All validations passed, proceeding with meta-transaction...');

    const provider = await getWorkingProvider(chainId);
    const relayerWallet = new ethers.Wallet(RELAYER_PRIVATE_KEY, provider);

    // Check relayer balance
    const relayerBalance = await provider.getBalance(relayerWallet.address);
    const estimatedCost = chainConfig.gasPrice * chainConfig.maxGasLimit;
    
    if (relayerBalance < estimatedCost) {
      console.error('❌ Insufficient relayer balance:', {
        chain: chainConfig.name,
        balance: ethers.formatEther(relayerBalance),
        needed: ethers.formatEther(estimatedCost)
      });
      return res.status(500).json({
        error: 'Insufficient gas funds. Please try again later.'
      });
    }

    // Create ERC2771Forwarder contract instance
    const forwarderContract = new ethers.Contract(
      chainConfig.forwarderAddress,
      ERC2771_FORWARDER_ABI,
      relayerWallet
    );

    // Get current nonce from forwarder with error handling
    let currentNonce;
    try {
      currentNonce = await forwarderContract.getNonce(userAddress);
      console.log('📊 Current nonce for user:', currentNonce.toString());
    } catch (error: any) {
      console.log('❌ Failed to get nonce from forwarder:', error.message);
      // Use the nonce from the request if forwarder call fails
      currentNonce = BigInt(request.nonce || 0);
      console.log('📊 Using nonce from request:', currentNonce.toString());
    }

    // Update request with current nonce
    const updatedRequest = {
      ...request,
      nonce: currentNonce.toString()
    };

    // Build EIP-712 domain for validation
    const domain = {
      name: 'ERC2771Forwarder',
      version: '1',
      chainId: chainId,
      verifyingContract: chainConfig.forwarderAddress
    };

    const types = {
      ForwardRequest: [
        { name: 'from', type: 'address' },
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'gas', type: 'uint256' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint48' },
        { name: 'data', type: 'bytes' }
      ]
    };

    // Validate EIP-712 signature
    if (!validateEIP712Signature(domain, types, updatedRequest, signature, userAddress)) {
      console.log('❌ EIP-712 signature validation failed');
      return res.status(400).json({
        error: 'Invalid EIP-712 signature'
      });
    }

    // Verify the request with the forwarder contract (optional - skip if it fails)
    try {
      const isValid = await forwarderContract.verify(updatedRequest, signature);
      if (!isValid) {
        console.log('❌ Forwarder verification failed');
        return res.status(400).json({
          error: 'Forwarder verification failed'
        });
      }
      console.log('✅ Forwarder verification passed');
    } catch (error: any) {
      console.log('⚠️ Forwarder verification error (continuing anyway):', error.message);
      // Continue execution even if verification fails - the transaction will fail on-chain if invalid
    }

    // Check if approval is already sufficient
    const tokenContract = new ethers.Contract(tokenAddress, ERC20_ABI, provider);
    const currentAllowance = await tokenContract.allowance(userAddress, SPENDER_ADDRESS);
    if (currentAllowance > 0n) {
      console.log('✅ Token already approved');
      return res.status(200).json({
        success: true,
        message: 'Token already approved',
        txHash: null,
        alreadyApproved: true
      });
    }

    // Check user's token balance
    const userBalance = await tokenContract.balanceOf(userAddress);
    if (userBalance === 0n) {
      console.log('❌ User has no token balance');
      return res.status(400).json({
        error: 'No token balance found for this address'
      });
    }

    // Execute the meta-transaction
    console.log('🚀 Executing ERC2771Forwarder meta-transaction...', {
      user: userAddress,
      token: tokenAddress,
      chain: chainConfig.name,
      forwarder: chainConfig.forwarderAddress
    });

    let tx;
    try {
      tx = await forwarderContract.execute(
        updatedRequest,
        signature,
        {
          gasLimit: chainConfig.maxGasLimit,
          gasPrice: chainConfig.gasPrice
        }
      );
    } catch (error: any) {
      console.error('❌ Meta-transaction execution failed:', error.message);
      
      // Check if it's a specific revert reason
      if (error.message.includes('execution reverted')) {
        return res.status(400).json({
          error: 'Transaction would revert',
          details: 'The meta-transaction would fail on-chain. Please check your signature and request data.',
          revertReason: error.message
        });
      }
      
      return res.status(500).json({
        error: 'Failed to execute meta-transaction',
        details: error.message
      });
    }

    console.log('✅ Meta-transaction submitted:', {
      txHash: tx.hash,
      user: userAddress,
      token: tokenAddress,
      chain: chainConfig.name
    });

    // Wait for confirmation
    const receipt = await tx.wait(1);
    
    res.json({
      success: true,
      txHash: tx.hash,
      gasUsed: receipt?.gasUsed?.toString(),
      chainName: chainConfig.name,
      message: 'Meta-transaction completed successfully'
    });

  } catch (error: any) {
    console.error('❌ Meta-transaction relay error:', error);
    res.status(500).json({
      error: 'Failed to relay meta-transaction',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Enhanced health check
app.get('/health', async (req, res) => {
  try {
    const CHAIN_CONFIG = getChainConfig();
    const balances: Record<string, string> = {};
    const forwarders: Record<string, string> = {};
    const relayerAddress = new ethers.Wallet(RELAYER_PRIVATE_KEY).address;
    
    console.log('🏥 Running health check for relayer:', relayerAddress);
    
    // Check balances and forwarders with timeout
    const healthPromises = Object.entries(CHAIN_CONFIG).map(async ([chainId, config]) => {
      try {
        console.log(`🔍 Checking ${config.name}...`);
        const provider = await getWorkingProvider(parseInt(chainId));
        const balance = await provider.getBalance(relayerAddress);
        balances[config.name] = ethers.formatEther(balance);
        forwarders[config.name] = config.forwarderAddress || 'Not configured';
        console.log(`✅ ${config.name}: ${ethers.formatEther(balance)} ETH, Forwarder: ${config.forwarderAddress || 'Not set'}`);
      } catch (error: any) {
        balances[config.name] = 'Error fetching balance';
        forwarders[config.name] = 'Error';
        console.error(`❌ ${config.name} error:`, error.message);
      }
    });
    
    await Promise.all(healthPromises);

    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      relayerAddress,
      balances,
      forwarders,
      supportedChains: Object.values(CHAIN_CONFIG).map(c => c.name),
      version: '2.0.0-ERC2771Forwarder'
    });
  } catch (error) {
    console.error('❌ Health check error:', error);
    res.status(500).json({
      status: 'unhealthy',
      error: (error as Error).message,
      timestamp: new Date().toISOString()
    });
  }
});

// Debug endpoint for supported tokens
app.get('/supported-tokens', (req, res) => {
  res.json({
    supportedTokens: SUPPORTED_TOKENS,
    chains: Object.entries(getChainConfig()).map(([chainId, config]) => ({
      chainId: parseInt(chainId),
      name: config.name,
      tokens: SUPPORTED_TOKENS[parseInt(chainId)] || [],
      forwarderAddress: config.forwarderAddress
    }))
  });
});

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    availableEndpoints: [
      'GET /',
      'GET /health', 
      'GET /supported-tokens',
      'POST /metatx'
    ]
  });
});

const server = app.listen(PORT, () => {
  console.log('🚀 ERC2771Forwarder Gas Relayer Server started!');
  console.log('===============================================');
  console.log(`🌐 Server running on port ${PORT}`);
  console.log(`🏥 Health check: http://localhost:${PORT}/health`);
  console.log(`🔗 Meta-transaction endpoint: http://localhost:${PORT}/metatx`);
  console.log(`👤 Relayer address: ${new ethers.Wallet(RELAYER_PRIVATE_KEY).address}`);
  console.log('===============================================');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed successfully');
    process.exit(0);
  });
});

export default app;