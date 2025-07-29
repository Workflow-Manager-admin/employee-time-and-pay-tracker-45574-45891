#!/bin/bash
cd /home/kavia/workspace/code-generation/employee-time-and-pay-tracker-45574-45891/employee_time_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

