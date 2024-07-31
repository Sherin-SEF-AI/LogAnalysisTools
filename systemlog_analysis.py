import sys
import pandas as pd
import numpy as np
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, 
                             QFileDialog, QTextEdit, QLabel, QComboBox, QSpinBox, QDialog, QFormLayout)
from PyQt5.QtCore import Qt
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from datetime import datetime, timedelta
import random

class LogGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Log Generator")
        self.setGeometry(200, 200, 300, 200)
        
        layout = QFormLayout(self)
        
        self.num_entries = QSpinBox()
        self.num_entries.setRange(1, 1000000)
        self.num_entries.setValue(1000)
        layout.addRow("Number of Entries:", self.num_entries)
        
        self.log_type = QComboBox()
        self.log_type.addItems(["Server Logs", "Application Logs", "Security Logs"])
        layout.addRow("Log Type:", self.log_type)
        
        self.generate_button = QPushButton("Generate")
        self.generate_button.clicked.connect(self.accept)
        layout.addRow(self.generate_button)

class LogAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Log Analysis Tool")
        self.setGeometry(100, 100, 1000, 800)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout(self.central_widget)
        
        self.setup_ui()
        
        self.log_data = None
        self.timestamp_column = None

    def setup_ui(self):
        # File selection
        file_layout = QHBoxLayout()
        self.file_label = QLabel("No file selected")
        self.select_file_button = QPushButton("Select Log File")
        self.select_file_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.select_file_button)
        self.layout.addLayout(file_layout)

        # Analysis options
        analysis_layout = QHBoxLayout()
        self.analyze_button = QPushButton("Analyze Logs")
        self.analyze_button.clicked.connect(self.analyze_logs)
        self.detect_anomalies_button = QPushButton("Detect Anomalies")
        self.detect_anomalies_button.clicked.connect(self.detect_anomalies)
        self.visualize_button = QPushButton("Visualize Data")
        self.visualize_button.clicked.connect(self.visualize_data)
        analysis_layout.addWidget(self.analyze_button)
        analysis_layout.addWidget(self.detect_anomalies_button)
        analysis_layout.addWidget(self.visualize_button)
        self.layout.addLayout(analysis_layout)

        # Log generation and saving
        gen_layout = QHBoxLayout()
        self.generate_button = QPushButton("Generate Log Data")
        self.generate_button.clicked.connect(self.generate_log_data)
        self.save_button = QPushButton("Save Log Data")
        self.save_button.clicked.connect(self.save_log_data)
        gen_layout.addWidget(self.generate_button)
        gen_layout.addWidget(self.save_button)
        self.layout.addLayout(gen_layout)

        # Visualization options
        vis_layout = QHBoxLayout()
        self.vis_type_combo = QComboBox()
        self.vis_type_combo.addItems(["Time Series", "Histogram", "Pie Chart"])
        vis_layout.addWidget(QLabel("Visualization Type:"))
        vis_layout.addWidget(self.vis_type_combo)
        self.layout.addLayout(vis_layout)

        # Results display
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.layout.addWidget(self.results_text)

        # Matplotlib figure
        self.figure = plt.figure(figsize=(5, 4))
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(self.canvas)

    def select_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Log File", "", "Log Files (*.log *.txt *.csv);;All Files (*)")
        if file_name:
            self.file_label.setText(file_name)
            try:
                # Try to read the file with different methods
                self.log_data = self.parse_log_file(file_name)
                
                if self.log_data is None or self.log_data.empty:
                    raise ValueError("Could not parse the log file")
                
                self.identify_timestamp_column()
                self.results_text.setPlainText("File loaded successfully.")
            except Exception as e:
                self.results_text.setPlainText(f"Error loading file: {str(e)}")
                self.log_data = None

    def parse_log_file(self, file_name):
        if file_name.endswith('.csv'):
            return pd.read_csv(file_name)
        
        # Try different parsing methods for non-CSV files
        try:
            # Method 1: CSV-like format
            return pd.read_csv(file_name, sep=None, engine='python')
        except:
            pass

        try:
            # Method 2: Fixed-width format
            with open(file_name, 'r') as f:
                lines = f.readlines()
            if len(lines) > 1:
                # Guess column widths from the first two lines
                widths = [len(w) for w in lines[0].split()]
                return pd.read_fwf(file_name, widths=widths, header=None)
        except:
            pass

        try:
            # Method 3: Custom parsing for common log formats
            with open(file_name, 'r') as f:
                lines = f.readlines()
            parsed_lines = []
            for line in lines:
                # Split on common delimiters
                parts = line.split()
                if len(parts) >= 2:
                    timestamp = ' '.join(parts[:2])
                    message = ' '.join(parts[2:])
                    parsed_lines.append([timestamp, message])
            return pd.DataFrame(parsed_lines, columns=['Timestamp', 'Message'])
        except:
            pass

        return None

    def identify_timestamp_column(self):
        for column in self.log_data.columns:
            if 'time' in str(column).lower() or 'date' in str(column).lower():
                self.timestamp_column = column
                try:
                    self.log_data[self.timestamp_column] = pd.to_datetime(self.log_data[self.timestamp_column], infer_datetime_format=True)
                    break
                except:
                    continue

        if self.timestamp_column is None:
            self.results_text.setPlainText("Could not identify a timestamp column. Some features may be limited.")

    def analyze_logs(self):
        if self.log_data is None:
            self.results_text.setPlainText("Please select a log file first.")
            return

        analysis_result = "Log Analysis Results:\n\n"
        analysis_result += f"Total log entries: {len(self.log_data)}\n"
        analysis_result += f"Columns: {', '.join(self.log_data.columns)}\n\n"
        
        analysis_result += "Column Statistics:\n"
        for column in self.log_data.columns:
            analysis_result += f"{column}:\n"
            analysis_result += f"  - Unique values: {self.log_data[column].nunique()}\n"
            if self.log_data[column].dtype in ['int64', 'float64']:
                analysis_result += f"  - Mean: {self.log_data[column].mean():.2f}\n"
                analysis_result += f"  - Std Dev: {self.log_data[column].std():.2f}\n"
            analysis_result += "\n"

        analysis_result += f"\nSample data:\n{self.log_data.head().to_string()}\n"
        
        self.results_text.setPlainText(analysis_result)

    def detect_anomalies(self):
        if self.log_data is None or self.timestamp_column is None:
            self.results_text.setPlainText("Please select a log file with a valid timestamp column.")
            return

        # Anomaly detection based on message frequency
        hourly_counts = self.log_data.resample('H', on=self.timestamp_column).size()
        mean_count = hourly_counts.mean()
        std_count = hourly_counts.std()
        anomalies = hourly_counts[abs(hourly_counts - mean_count) > 2 * std_count]

        # Anomaly detection based on message content
        if 'Message' in self.log_data.columns:
            common_words = self.log_data['Message'].str.split(expand=True).stack().value_counts().head(10)
            rare_words = self.log_data['Message'].str.split(expand=True).stack().value_counts().tail(10)
        else:
            common_words = pd.Series()
            rare_words = pd.Series()

        anomaly_result = "Anomaly Detection Results:\n\n"
        if not anomalies.empty:
            anomaly_result += "Time-based anomalies detected:\n"
            for timestamp, count in anomalies.items():
                anomaly_result += f"{timestamp}: {count} entries (unusual activity)\n"
        else:
            anomaly_result += "No significant time-based anomalies detected.\n"

        if not common_words.empty:
            anomaly_result += "\nMost common words in logs:\n"
            anomaly_result += common_words.to_string() + "\n"
            anomaly_result += "\nRarest words in logs (potential anomalies):\n"
            anomaly_result += rare_words.to_string() + "\n"

        self.results_text.setPlainText(anomaly_result)

    def visualize_data(self):
        if self.log_data is None:
            self.results_text.setPlainText("Please select a log file first.")
            return

        vis_type = self.vis_type_combo.currentText()
        self.figure.clear()
        ax = self.figure.add_subplot(111)

        if vis_type == "Time Series" and self.timestamp_column:
            hourly_counts = self.log_data.resample('H', on=self.timestamp_column).size()
            ax.plot(hourly_counts.index, hourly_counts.values)
            ax.set_title("Log Entries Over Time")
            ax.set_xlabel("Time")
            ax.set_ylabel("Number of Entries")
            plt.xticks(rotation=45)
        elif vis_type == "Histogram":
            if self.timestamp_column:
                self.log_data[self.timestamp_column].dt.hour.hist(ax=ax, bins=24)
                ax.set_title("Distribution of Log Entries by Hour")
                ax.set_xlabel("Hour of Day")
                ax.set_ylabel("Number of Entries")
            else:
                self.results_text.setPlainText("Histogram requires a timestamp column.")
                return
        elif vis_type == "Pie Chart":
            if 'Message' in self.log_data.columns:
                message_types = self.log_data['Message'].str.split().str[0].value_counts().head(5)
                ax.pie(message_types.values, labels=message_types.index, autopct='%1.1f%%')
                ax.set_title("Top 5 Message Types")
            else:
                self.results_text.setPlainText("Pie chart requires a 'Message' column.")
                return

        self.canvas.draw()

    def generate_log_data(self):
        dialog = LogGeneratorDialog(self)
        if dialog.exec_():
            num_entries = dialog.num_entries.value()
            log_type = dialog.log_type.currentText()
            
            start_date = datetime.now() - timedelta(days=30)
            dates = [start_date + timedelta(seconds=i) for i in range(num_entries)]
            
            if log_type == "Server Logs":
                messages = [f"{'ERROR' if random.random() < 0.1 else 'INFO'}: Server {random.choice(['started', 'stopped', 'restarted', 'updated'])} - Process ID: {random.randint(1000, 9999)}" for _ in range(num_entries)]
            elif log_type == "Application Logs":
                messages = [f"{'ERROR' if random.random() < 0.1 else 'INFO'}: User {random.randint(1, 1000)} {random.choice(['logged in', 'logged out', 'performed action', 'encountered error'])}" for _ in range(num_entries)]
            else:  # Security Logs
                messages = [f"{'ALERT' if random.random() < 0.1 else 'INFO'}: {random.choice(['Authentication attempt', 'Firewall rule triggered', 'Port scan detected', 'File access'])} from IP: {'.'.join([str(random.randint(0, 255)) for _ in range(4)])}" for _ in range(num_entries)]
            
            self.log_data = pd.DataFrame({'Timestamp': dates, 'Message': messages})
            self.timestamp_column = 'Timestamp'
            self.results_text.setPlainText(f"Generated {num_entries} {log_type} entries.")

    def save_log_data(self):
        if self.log_data is None:
            self.results_text.setPlainText("No log data to save. Please generate or load log data first.")
            return
        
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Log Data", "", "CSV Files (*.csv);;All Files (*)")
        if file_name:
            self.log_data.to_csv(file_name, index=False)
            self.results_text.setPlainText(f"Log data saved to {file_name}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    analyzer = LogAnalyzer()
    analyzer.show()
    sys.exit(app.exec_())
