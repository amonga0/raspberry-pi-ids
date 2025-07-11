from flask import Flask, render_template_string # import Flask for creating a lightweight web server
import pandas as pd # import pandas for data manipulation from CSV file

# Initialize the Flask app
app = Flask(__name__)
CSV_FILE = "traffic_log.csv" # CSV file to read packet data from

# define HTML template with Chart.js for graphs and table for alerts
TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Raspberry Pi IDS Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial; padding: 20px; }
        h1 { color: #333; }
        .chart-container { width: 45%; display: inline-block; vertical-align: top; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #eee; }
    </style>
</head>
<body>
    <h1>Intrusion Detection Dashboard</h1>

    <div class="chart-container">
        <h3>Protocol Distribution</h3>
        <canvas id="protocolChart"></canvas>
    </div>
    <div class="chart-container">
        <h3>Top Destination Ports</h3>
        <canvas id="portChart"></canvas>
    </div>

    <h2>Recent Alerts</h2>
    <table>
        <tr><th>Timestamp</th><th>Source IP</th><th>Alert</th></tr>
        {% for row in alerts %}
        <tr>
            <td>{{ row['Timestamp'] }}</td>
            <td>{{ row['Source IP'] }}</td>
            <td>{{ row['Alert'] if row['Alert'] else "None" }}</td>
        </tr>
        {% endfor %}
    </table>

    <script>
        // Protocol Distribution Pie Chart
        const protocolChart = new Chart(document.getElementById('protocolChart').getContext('2d'), {
            type: 'pie',
            data: {
                labels: {{ protocol_labels|tojson }},
                datasets: [{ data: {{ protocol_data|tojson }}, backgroundColor: ['#f66', '#6f6', '#66f', '#fc3', '#3cf'] }]
            }
        });

        // Top Destination Ports Bar Chart
        const portChart = new Chart(document.getElementById('portChart').getContext('2d'), {
            type: 'bar',
            data: {
                labels: {{ port_labels|tojson }},
                datasets: [{
                    label: 'Packet Count',
                    data: {{ port_data|tojson }},
                    backgroundColor: '#3399ff'
                }]
            },
            options: {
                scales: { y: { beginAtZero: true } }
            }
        });
    </script>
</body>
</html>
'''

# Define the route for the homepage
@app.route('/')
def dashboard():
    try:
        # load the CSV file into a pandas DataFrame
        df = pd.read_csv(CSV_FILE)

        # drop any incomplete rows to prevent visualization errors (troubleshooting)
        df = df.dropna(subset=["Timestamp", "Protocol", "Source IP"])

        # filter only rows with a non-empty "Alert" field and take the 10 most recent
        alerts = df[df['Alert'].notna() & (df['Alert'] != "")][['Timestamp', 'Source IP', 'Alert']] \
                 .tail(10).to_dict(orient='records')

        # count how many packets use each protocol
        protocol_counts = df['Protocol'].value_counts()
        protocol_labels = [str(p) for p in protocol_counts.index.tolist()]
        protocol_data = [int(p) for p in protocol_counts.values.tolist()]

        # count the most common destination ports
        port_counts = df['Destination Port'].value_counts().head(6) # top 6
        port_labels = [str(p) for p in port_counts.index.tolist()]
        port_data = [int(p) for p in port_counts.values.tolist()]

        # render the HTML template and inject all the data
        return render_template_string(
            TEMPLATE,
            protocol_labels=protocol_labels,
            protocol_data=protocol_data,
            port_labels=port_labels,
            port_data=port_data,
            alerts=alerts
        )

    # exception handling for any CSV parsing or file read errors
    except Exception as e:
        return f"<h1>Error loading data: {e}</h1>"

# run the Flask server, port 5000
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)