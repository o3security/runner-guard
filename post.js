const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs-extra");

async function readAndLog(logType, logPath) {
  try {
    if (await fs.pathExists(logPath)) {
      core.info(`--- ROC ${logType} ---`);
      const logContent = await fs.readFile(logPath, "utf8");
      core.info(logContent);
      core.info(`--- End ROC ${logType} ---`);
    } else {
      core.info(`ROC ${logType} log file not found at ${logPath}`);
    }
  } catch (error) {
    core.warning(`Error reading ROC ${logType} log: ${error.message}`);
  }
}

async function cleanup() {
  try {
    await readAndLog("stdout", "/tmp/roc-stdout.log");
    await readAndLog("stderr", "/tmp/roc-stderr.log");

    const rocPid = core.getState("rocPid");
    if (rocPid) {
      core.info(`Stopping ROC process with PID: ${rocPid}`);
      // Use sudo to ensure permissions to kill the process started with sudo
      await exec.exec("sudo", ["kill", "-SIGINT", rocPid]);
      core.info(`Successfully sent SIGINT to ROC process ${rocPid}.`);
    } else {
      core.info("No ROC PID found, skipping cleanup.");
    }
  } catch (error) {
    // Don't fail the workflow if cleanup fails, just log it
    core.warning(`Failed to stop ROC process: ${error.message}`);
  }
}

cleanup();
