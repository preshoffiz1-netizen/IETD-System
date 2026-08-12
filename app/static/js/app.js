// IETDS front-end helpers: confirmation dialogs, dynamic rule-condition rows,
// and lightweight chart bootstrapping. No browser storage APIs are used.

document.addEventListener("DOMContentLoaded", () => {
    // Confirmation dialogs for destructive actions.
    document.querySelectorAll("[data-confirm]").forEach((el) => {
        el.addEventListener("submit", (event) => {
            const message = el.getAttribute("data-confirm") || "Are you sure?";
            if (!window.confirm(message)) {
                event.preventDefault();
            }
        });
    });

    // Rule builder: add/remove condition rows.
    const addConditionBtn = document.getElementById("add-condition-btn");
    if (addConditionBtn) {
        addConditionBtn.addEventListener("click", () => {
            const container = document.getElementById("condition-rows");
            const template = document.getElementById("condition-row-template");
            const clone = template.content.cloneNode(true);
            container.appendChild(clone);
        });
        document.getElementById("condition-rows").addEventListener("click", (event) => {
            if (event.target.matches(".remove-condition-btn")) {
                event.target.closest(".rule-condition-row").remove();
            }
        });
    }
});

function renderDoughnutChart(canvasId, labels, values, colors) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === "undefined") return;
    new Chart(el, {
        type: "doughnut",
        data: { labels, datasets: [{ data: values, backgroundColor: colors }] },
        options: { plugins: { legend: { position: "bottom" } } },
    });
}

function renderLineChart(canvasId, labels, values, label) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === "undefined") return;
    new Chart(el, {
        type: "line",
        data: { labels, datasets: [{ label, data: values, borderColor: "#2e7dfd", backgroundColor: "rgba(46,125,253,.1)", fill: true, tension: .3 }] },
        options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } },
    });
}

function renderBarChart(canvasId, labels, values, label, color) {
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === "undefined") return;
    new Chart(el, {
        type: "bar",
        data: { labels, datasets: [{ label, data: values, backgroundColor: color || "#2e7dfd" }] },
        options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } },
    });
}
