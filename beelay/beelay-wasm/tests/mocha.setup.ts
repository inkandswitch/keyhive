// This file configures Mocha for running WASM tests
import 'mocha';

// Set timeout to a higher value for WASM initialization
const TEST_TIMEOUT = 60000; // 60 seconds
this.timeout(TEST_TIMEOUT);

// Global error handler
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});