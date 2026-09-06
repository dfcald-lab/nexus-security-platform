async function showDevice(deviceId) {
    try {
        const response = await fetch(
            "/api/device/" + encodeURIComponent(deviceId)
        );

        if (!response.ok) {
            throw new Error("Device lookup failed");
        }

        const device = await response.json();

        document.getElementById("deviceTitle").textContent =
            device.device_type || "UNKNOWN";

        document.getElementById("deviceBody").innerHTML =
            "<strong>Device ID:</strong> " +
                escapeHtml(device.device_id) + "<br>" +
            "<strong>Vendor:</strong> " +
                escapeHtml(device.vendor) + "<br>" +
            "<strong>IP:</strong> " +
                escapeHtml(device.ip) + "<br>" +
            "<strong>Port:</strong> " +
                escapeHtml(device.port) + "<br>" +
            "<strong>VLAN:</strong> " +
                escapeHtml(device.vlan) + "<br>" +
            "<strong>Observations:</strong> " +
                escapeHtml(device.observations);

        document.getElementById("deviceModal").style.display = "block";

    } catch (error) {
        console.error(error);
    }
}


function closeDevice() {
    document.getElementById("deviceModal").style.display = "none";
}


function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = String(value);
    return div.innerHTML;
}

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".device-row").forEach((row) => {
        row.addEventListener("click", () => {
            showDevice(row.dataset.deviceId);
        });
    });

    const close = document.getElementById("deviceClose");

    if (close) {
        close.addEventListener("click", closeDevice);
    }

    const modal = document.getElementById("deviceModal");

    if (modal) {
        modal.addEventListener("click", (event) => {
            if (event.target === modal) {
                closeDevice();
            }
        });
    }
});
