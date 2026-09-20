document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("scan-form");
    const scanButton = document.getElementById("scan-button");

    const scanProgress = document.getElementById("scan-progress");
    const progressBar = document.getElementById("progress-bar");
    const progressPercent = document.getElementById("progress-percent");
    const progressMessage = document.getElementById("progress-message");
    const progressTrack = document.querySelector(".progress-track");

    if (!scanForm) {
        return;
    }

    const stages = [
        {
            id: "step-validation",
            progress: 12,
            message: "Validating target URL..."
        },
        {
            id: "step-recon",
            progress: 25,
            message: "Collecting basic reconnaissance information..."
        },
        {
            id: "step-nmap",
            progress: 40,
            message: "Running Nmap port and service scan..."
        },
        {
            id: "step-http",
            progress: 55,
            message: "Analyzing HTTP response..."
        },
        {
            id: "step-headers",
            progress: 67,
            message: "Checking security headers..."
        },
        {
            id: "step-cookies",
            progress: 77,
            message: "Analyzing cookie security..."
        },
        {
            id: "step-vulnerability",
            progress: 88,
            message: "Running controlled vulnerability assessment..."
        },
        {
            id: "step-risk",
            progress: 100,
            message: "Classifying risks and generating report..."
        }
    ];

    function updateProgress(stageIndex) {
        const stage = stages[stageIndex];

        if (!stage) {
            return;
        }

        stages.forEach((item, index) => {
            const element = document.getElementById(item.id);

            if (!element) {
                return;
            }

            element.classList.remove("active", "completed");

            if (index < stageIndex) {
                element.classList.add("completed");
            } else if (index === stageIndex) {
                element.classList.add("active");
            }
        });

        progressBar.style.width = `${stage.progress}%`;
        progressPercent.textContent = `${stage.progress}%`;
        progressMessage.textContent = stage.message;

        progressTrack.setAttribute(
            "aria-valuenow",
            stage.progress
        );
    }

    function completeProgress() {
        stages.forEach((stage) => {
            const element = document.getElementById(stage.id);

            if (element) {
                element.classList.remove("active");
                element.classList.add("completed");
            }
        });

        progressBar.style.width = "100%";
        progressPercent.textContent = "100%";
        progressMessage.textContent = "Scan completed. Loading results...";

        progressTrack.setAttribute("aria-valuenow", "100");
    }

    function showError(message) {
        progressMessage.textContent = message;
        progressMessage.classList.add("error");

        scanButton.disabled = false;
        scanButton.textContent = "Start Scan";
    }

    async function pollScanStatus(jobId) {
        try {
            const response = await fetch(`/scan-status/${jobId}`);

            if (!response.ok) {
                throw new Error("Could not retrieve scan status.");
            }

            const data = await response.json();

            /*
             * The Flask backend reports the current stage.
             *
             * Example:
             * {
             *     "status": "running",
             *     "current_stage": "Nmap service scan"
             * }
             */

            const currentStage = data.current_stage;

            if (currentStage) {
                const stageIndex = stages.findIndex(
                    (stage) =>
                        stage.message.toLowerCase().includes(
                            currentStage.toLowerCase()
                        ) ||
                        currentStage.toLowerCase().includes(
                            stage.id.replace("step-", "").replace("-", " ")
                        )
                );

                if (stageIndex !== -1) {
                    updateProgress(stageIndex);
                }
            }

            if (data.status === "completed") {
                completeProgress();

                setTimeout(() => {
                    window.location.href = `/scan-results/${jobId}`;
                }, 500);

                return;
            }

            if (data.status === "failed") {
                showError(
                    data.message || "The scan failed."
                );

                return;
            }

            setTimeout(() => {
                pollScanStatus(jobId);
            }, 500);

        } catch (error) {
            showError(
                "Unable to retrieve scan progress. Please check the server."
            );

            console.error(error);
        }
    }

    scanForm.addEventListener("submit", async (event) => {
        /*
         * This is the important part.
         *
         * Prevent the browser from navigating directly to /scan.
         */
        event.preventDefault();

        const formData = new FormData(scanForm);

        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";

        scanProgress.hidden = false;

        progressMessage.classList.remove("error");

        updateProgress(0);

        try {
            const response = await fetch(scanForm.action, {
                method: "POST",
                body: formData
            });

            if (!response.ok) {
                throw new Error("Failed to start the scan.");
            }

            const data = await response.json();

            if (!data.job_id) {
                throw new Error("The server did not return a scan job ID.");
            }

            /*
             * Flask has now started the background scan.
             *
             * Example:
             * {
             *     "job_id": "...",
             *     "status": "started"
             * }
             */

            updateProgress(0);

            pollScanStatus(data.job_id);

        } catch (error) {
            showError(
                error.message || "Unable to start the scan."
            );

            console.error(error);
        }
    });
});