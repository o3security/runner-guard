const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs-extra");
const { spawn } = require("child_process");

async function cloneAndPrepareROCBinary() {
  const repoDir = "/tmp/roc-agent";
  const binaryPath = "/tmp/roc-agent/roc";

  // Clone the repository
  core.info(`Cloning ROC agent repository to: ${repoDir}`);
  await exec.exec("git", [
    "clone",
    "https://github.com/Securable-ai/roc-agent.git",
    repoDir,
  ]);

  core.info(`Making ROC binary executable at ${binaryPath}`);
  await exec.exec("chmod", ["+x", binaryPath]);

  return binaryPath;
}

async function run() {
  try {
    core.info("Starting ROC Action...");

    // Get inputs from workflow
    const rocBinaryPath = core.getInput("roc_binary_path", {
      required: false, // No longer required since we'll clone the repo if not provided
    });
    const setupDependencies = core.getInput("setup_dependencies") === "true";

    // Determine the path for the ROC binary
    let finalROCBinaryPath;
    if (rocBinaryPath) {
      // Use the provided path if specified (for backward compatibility)
      finalROCBinaryPath = rocBinaryPath;
      core.info(`Using provided ROC binary path: ${finalROCBinaryPath}`);
    } else {
      // Clone the repository and use the binary from there
      core.info(
        "ROC binary path not provided, cloning repository from GitHub...",
      );
      finalROCBinaryPath = await cloneAndPrepareROCBinary();
    }

    if (setupDependencies) {
      core.info("Setting up dependencies...");
      await exec.exec("sudo", ["apt-get", "update"]);
      await exec.exec("sudo", [
        "apt-get",
        "install",
        "-y",
        "curl",
        "iptables",
        "tshark",
        "libpcap-dev",
      ]);
    }

    const watchDir = core.getInput("watch");
    if (watchDir) {
      core.info(`Ensuring watch directory exists at ${watchDir}`);
      await fs.ensureDir(watchDir);
    }

    core.info(`Making ROC binary executable at ${finalROCBinaryPath}`);
    await exec.exec("chmod", ["+x", finalROCBinaryPath]);

    // Construct arguments for the roc binary
    const rocArgs = [finalROCBinaryPath];

    const inputs = {
      "server-url": core.getInput("server_url", { required: true }),
      "api-key": core.getInput("api_key", { required: true }),
      "project-name": core.getInput("project_name", { required: true }),
      pcap: core.getInput("pcap"),
      watch: watchDir,
      patterns: core.getInput("patterns"),
      "network-config": core.getInput("network_config"),
      interface: core.getInput("interface"),
      "ssl-lib": core.getInput("ssl_lib"),
      "ssl-version": core.getInput("ssl_version"),
      "pksize-lim": core.getInput("pksize_lim"),
      "rotation-interval": core.getInput("rotation_interval"),
      "ecap-output-folder": core.getInput("ecap_output_folder"),
      source: core.getInput("source"),
      "splunk-url": core.getInput("splunk_url"),
      "splunk-token": core.getInput("splunk_token"),
      "es-url": core.getInput("es_url"),
      "es-index": core.getInput("es_index"),
      "es-user": core.getInput("es_user"),
      "es-pass": core.getInput("es_pass"),
      config: core.getInput("config"),
    };

    for (const [key, value] of Object.entries(inputs)) {
      if (value) {
        rocArgs.push(`--${key}`, value);
      }
    }

    if (core.getInput("debug") === "true") {
      rocArgs.push("--debug");
    }

    // Log ROC output for debugging
    const outStream = fs.openSync("/tmp/roc-stdout.log", "a");
    const errStream = fs.openSync("/tmp/roc-stderr.log", "a");

    core.info(`Running command: sudo ${rocArgs.join(" ")}`);

    // Spawn the process in the background (detached)
    const rocProcess = spawn("sudo", rocArgs, {
      detached: true,
      stdio: ["ignore", outStream, errStream],
    });

    // The action's main script can exit, but the child process will continue running.
    // The 'post' script will handle its termination.
    rocProcess.unref();

    // Save the PID to state for the post-action script to use
    core.saveState("rocPid", rocProcess.pid);
    core.setOutput("roc_pid", rocProcess.pid);
    core.info(
      `ROC process started in the background with PID: ${rocProcess.pid}`,
    );
  } catch (error) {
    core.setFailed(`Action failed with error: ${error.message}`);
  }
}

run();
