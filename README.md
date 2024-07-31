# LogAnalysisTools
Python GUI application for SystemLogAnalysis Tool

Log Analysis Tool

Overview

The Log Analysis Tool is a Python application built using PySide6 and pandas. It provides an interface for loading, analyzing, filtering, and searching system log files. The tool supports real-time updates and allows users to generate sample log data.

Features

Load Log Files: Open and load log files in .log or .txt formats.

Analyze Logs: Analyze the loaded log file for errors and view summary statistics.

Filter Logs: Filter logs by severity level (INFO, WARNING, ERROR, DEBUG).

Search Logs: Search for specific keywords within the logs.

Generate Log Data: Create and save sample log data with a specified number of entries.

Real-Time Updates: Monitor log file changes in real-time.

Requirements

Python 3.6+

PySide6

pandas

You can install the required packages using pip:


bash

Copy code

pip install PySide6 pandas

Installation

Clone the repository or download the source code.

Install the required Python packages.


Run the application using the following command:

bash

Copy code

python systemlog_analysis.py

Usage

Load Log File: Click on the "Load Log File" button to open a file dialog and select your log file.

Analyze Logs: Click on the "Analyze Logs" button to check for errors and view summary statistics.

Filter Logs: Use the dropdown menu to select a log level and click on the "Filter Logs" button to view only the logs of that level.

Remove Filter: Click on the "Remove Filter" button to reset the log display to show all logs.

Search Logs: Enter a keyword in the search field and click on the "Search Logs" button to search for that keyword in the logs.

Generate Log Data: Click on the "Generate Log Data" button to create sample log data. Specify the number of entries and save the generated file.

Troubleshooting

Qt Platform Plugin Errors: If you encounter errors related to the Qt platform plugin (e.g., "xcb" plugin), make sure you have the necessary Qt libraries installed on your system. For Linux, you may need to install additional packages like libxcb-cursor0.


Scrolling Issues: Ensure the QTextEdit widget is properly configured to support scrolling by setting appropriate scrollbar policies.
