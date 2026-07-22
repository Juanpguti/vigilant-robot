module.exports = {
  testEnvironment: 'node',
  collectCoverageFrom: ['src/**/*.js'],
  coverageThreshold: {
    global: { statements: 80, branches: 50, functions: 70, lines: 80 },
  },
};
