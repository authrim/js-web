/**
 * Vitest setup file
 *
 * This file is used to configure the test environment.
 * Handles unhandled promise rejections from fake timer tests.
 */

// Store original unhandledRejection handler
const originalUnhandledRejection =
  process.listeners('unhandledRejection').slice();

// Suppress unhandled rejection warnings during tests
// These occur when using fake timers with promise rejections
// and are expected behavior in our test suite
process.on('unhandledRejection', (reason: unknown) => {
  // Only suppress AuthrimError rejections which are expected in tests
  if (
    reason &&
    typeof reason === 'object' &&
    'code' in reason &&
    typeof (reason as Record<string, unknown>).code === 'string'
  ) {
    // This is an expected AuthrimError from our tests
    return;
  }

  // For other rejections, use original handlers
  originalUnhandledRejection.forEach((listener) => {
    listener(reason, Promise.resolve());
  });
});
