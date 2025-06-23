// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

document.addEventListener('DOMContentLoaded', function () {
    // Helper function to create charts
    function createChart(canvasId, type, labels, data, options = {}) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        };

        new Chart(canvas, {
            type: type,
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: [
                        '#4e73df',
                        '#1cc88a',
                        '#36b9cc',
                        '#f6c23e',
                        '#e74a3b'
                    ]
                }]
            },
            options: { ...defaultOptions, ...options }
        });
    }

    // Create Protocol Chart
    const protocolChart = document.getElementById('protocolChart');
    if (protocolChart) {
        const protocols = Array.from(document.querySelectorAll('tr td:first-child'))
            .filter(td => td.closest('table').querySelector('th').textContent === 'Protocol')
            .map(td => td.textContent);
        const protocolCounts = Array.from(document.querySelectorAll('tr td:last-child'))
            .filter(td => td.closest('table').querySelector('th').textContent === 'Protocol')
            .map(td => parseInt(td.textContent));
        createChart('protocolChart', 'doughnut', protocols, protocolCounts);
    }

    // Create Device Type Chart
    const deviceTypeChart = document.getElementById('deviceTypeChart');
    if (deviceTypeChart && window.deviceTypeData) {
        createChart('deviceTypeChart', 'pie', 
            window.deviceTypeData.map(d => d.deviceType),
            window.deviceTypeData.map(d => d.count)
        );
    }

    // Create Event Type Chart
    const eventTypeChart = document.getElementById('eventTypeChart');
    if (eventTypeChart && window.eventTypeData) {
        createChart('eventTypeChart', 'bar',
            window.eventTypeData.map(d => d.eventType),
            window.eventTypeData.map(d => d.count),
            {
                indexAxis: 'y',
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        );
    }

    // Create Destination IP Chart
    const destIpChart = document.getElementById('destIpChart');
    if (destIpChart && window.destIpData) {
        createChart('destIpChart', 'bar',
            window.destIpData.map(d => d.ip),
            window.destIpData.map(d => d.count),
            {
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        );
    }

    // Create Malware Type Chart
    const malwareTypeChart = document.getElementById('malwareTypeChart');
    if (malwareTypeChart && window.malwareTypeData) {
        createChart('malwareTypeChart', 'doughnut',
            window.malwareTypeData.map(d => d.eventType),
            window.malwareTypeData.map(d => d.count)
        );
    }

    // Create Threat Severity Chart
    const threatSeverityChart = document.getElementById('threatSeverityChart');
    if (threatSeverityChart && window.threatSeverityData) {
        createChart('threatSeverityChart', 'pie',
            window.threatSeverityData.map(d => d.severity),
            window.threatSeverityData.map(d => d.count)
        );
    }

    // Update logs in last 24h
    const logsLast24h = document.getElementById('logsLast24h');
    if (logsLast24h && window.recentLogsCount) {
        logsLast24h.textContent = window.recentLogsCount;
    }
});
