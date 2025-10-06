/**
 * Example test file to validate Jest setup
 */

describe('AI Software Scanner', () => {
  test('should be able to run basic tests', () => {
    expect(1 + 1).toBe(2);
  });

  test('should have proper project structure', () => {
    // This test validates that our test environment is working
    const testValue = 'ai-software-scanner';
    expect(testValue).toBeDefined();
    expect(typeof testValue).toBe('string');
  });
});