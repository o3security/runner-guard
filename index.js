const core = require("@actions/core");
const exec = require("@actions/exec");
const fs = require("fs-extra");
const path = require("path");
const { spawn } = require("child_process");

async function run() {
    try {
        const patternsYamlContent = core.getInput("patterns_yaml", {
            required: true,
        });
        const dockerImage = "public.ecr.aws/f9o7b7m0/roc";
        const serverUrl = core.getInput("server_url", { required: true });
        const apiKey = core.getInput("api_key", { required: true });
        const projectName = core.getInput("project_name", { required: true });

        const patternsFileInsideContainer = "/tmp/roc-config/pattern.yaml";
        const watchDirInsideContainer = "/tmp/roc-output";
        const libsslContainerPath = "/usr/lib64/libssl.so.3";
        const libcryptoContainerPath = "/usr/lib64/libcrypto.so.3";

        const libsslHostPath =
            core.getInput("libssl_host_path", { required: false }) ||
            "/lib/x86_64-linux-gnu/libssl.so.3";
        const libcryptoHostPath =
            core.getInput("libcrypto_host_path", { required: false }) ||
            "/lib/x86_64-linux-gnu/libcrypto.so.3";

        const containerName =
            core.getInput("container_name", { required: false }) ||
            "roc-action-container";
        const outputDirHostPath =
            core.getInput("output_dir", { required: false }) ||
            "./roc-action-output";
        const extraDockerArgs =
            core.getInput("args", { required: false }) || "";

        const workspace = process.env.GITHUB_WORKSPACE;

        const hostConfigDir = path.join(workspace, "roc-config-action");
        const hostOutputDir = path.join(
            workspace,
            outputDirHostPath.replace("./", ""),
        );

        await fs.ensureDir(hostConfigDir);
        await fs.ensureDir(hostOutputDir);

        core.info(`Host Config Dir: ${hostConfigDir}`);
        core.info(`Host Output Dir: ${hostOutputDir}`);

        const hostPatternFilePath = path.join(hostConfigDir, "pattern.yaml");
        await fs.writeFile(hostPatternFilePath, patternsYamlContent);
        core.info(
            `User-provided patterns file written to: ${hostPatternFilePath}`,
        );

        const dockerRunCmd = [
            "docker",
            "run",
            "-d",
            "--name",
            containerName,
            "--privileged",
            "--pid=host",
            "--network=host",
            "-v",
            "/proc:/proc",
            "-v",
            "/sys:/sys",
            "-v",
            `${libsslHostPath}:${libsslContainerPath}`,
            "-v",
            `${libcryptoHostPath}:${libcryptoContainerPath}`,
            "-v",
            `${hostOutputDir}:/tmp/roc-output`,
            "-v",
            `${hostConfigDir}:/tmp/roc-config:ro`,
            ...extraDockerArgs.split(" "),
            dockerImage,
            "--server-url",
            serverUrl,
            "--api-key",
            apiKey,
            "--project-name",
            projectName,
            "--patterns",
            patternsFileInsideContainer,
            "--watch",
            watchDirInsideContainer,
        ].filter((arg) => arg !== "");

        core.info(`Running Docker command: ${dockerRunCmd.join(" ")}`);

        // Use spawn to run Docker in detached mode so the action doesn't hang
        return new Promise((resolve, reject) => {
            const dockerProcess = spawn(
                dockerRunCmd[0],
                dockerRunCmd.slice(1),
                {
                    stdio: ["ignore", "pipe", "pipe"], // ignore stdin, pipe stdout and stderr
                },
            );

            let output = "";
            let errorOutput = "";

            dockerProcess.stdout.on("data", (data) => {
                output += data.toString();
            });

            dockerProcess.stderr.on("data", (data) => {
                errorOutput += data.toString();
            });

            dockerProcess.on("close", (code) => {
                if (code !== 0) {
                    core.setFailed(
                        `Docker run failed with exit code ${code}. Error: ${errorOutput}`,
                    );
                    reject(new Error(`Docker run failed: ${errorOutput}`));
                    return;
                }

                // Verify that the container was created successfully
                exec.exec("docker", [
                    "ps",
                    "--filter",
                    `name=${containerName}`,
                    "--format",
                    "{{.Names}}",
                ])
                    .then((exitCode) => {
                        if (exitCode !== 0) {
                            core.setFailed(
                                `Failed to verify container creation. Docker errors: ${errorOutput}`,
                            );
                            reject(
                                new Error(
                                    `Failed to verify container creation: ${errorOutput}`,
                                ),
                            );
                            return;
                        }

                        // Add a short delay to ensure the container is fully ready
                        setTimeout(() => {
                            core.setOutput("container_name", containerName);
                            core.info(
                                `Container '${containerName}' started and ready for external interaction.`,
                            );
                            resolve();
                        }, 5000);
                    })
                    .catch((err) => {
                        core.setFailed(
                            `Failed to verify container: ${err.message}`,
                        );
                        reject(err);
                    });
            });

            dockerProcess.on("error", (error) => {
                core.setFailed(`Docker process failed: ${error.message}`);
                reject(error);
            });
        });
    } catch (error) {
        core.setFailed(error.message);
    }
}

run();
