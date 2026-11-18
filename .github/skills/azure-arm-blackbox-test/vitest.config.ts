import { defineConfig, mergeConfig } from "vitest/config";
import { defaultVitestConfig } from "../../../vitest.config.mts";

export default mergeConfig(
  defaultVitestConfig,
  defineConfig({
    test: {
      name: "azure-arm-blackbox-test",
      include: ["tests/**/*.test.ts"],
      coverage: {
        exclude: ["**/tests/**", "**/scripts/cli.ts"],
      },
      restoreMocks: true,
      testTimeout: 30_000,
    },
  }),
);
