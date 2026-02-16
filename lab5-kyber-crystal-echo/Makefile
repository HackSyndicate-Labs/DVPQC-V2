# Crystal Echo Lab - Makefile
# ===========================

PYTHON := python3
PIP := pip3
PYTEST := pytest
VENV := venv

.PHONY: all setup test fuzz clean help

# Default target
all: help

# Setup virtual environment and dependencies
setup:
	@echo "Creating virtual environment..."
	$(PYTHON) -m venv $(VENV)
	@echo "Installing dependencies..."
	. $(VENV)/bin/activate && $(PIP) install -r requirements.txt
	@echo ""
	@echo "Setup complete! Activate with: source $(VENV)/bin/activate"

# Run basic tests
test: test-basic test-compliance test-edge

test-basic:
	@echo "Running basic tests..."
	$(PYTEST) tests/test_basic.py -v

test-compliance:
	@echo "Running compliance tests..."
	$(PYTEST) tests/test_compliance.py -v

test-edge:
	@echo "Running edge case tests..."
	$(PYTEST) tests/test_edge_cases.py -v

# Run all tests
test-all:
	@echo "Running all tests..."
	$(PYTEST) tests/ -v --tb=short

# Generate fuzzing corpus
corpus:
	@echo "Generating fuzzing corpus..."
	cd fuzzing && $(PYTHON) generate_seeds.py
	@echo "Corpus generated in fuzzing/corpus/seed_ciphertexts/"

# Run fuzzing with Atheris
fuzz: fuzz-diff

fuzz-decaps:
	@echo "Starting decapsulation fuzzer..."
	cd fuzzing/harness && $(PYTHON) fuzz_decaps.py -max_len=1088 -runs=50000

fuzz-ciphertext:
	@echo "Starting structure-aware fuzzer..."
	cd fuzzing/harness && $(PYTHON) fuzz_ciphertext.py -max_len=1088 -runs=50000

fuzz-diff:
	@echo "Starting differential fuzzer..."
	cd fuzzing/harness && $(PYTHON) differential_fuzz.py -max_len=1088 -runs=50000

# Run the solution exploit
exploit:
	@echo "Running solution exploit..."
	$(PYTHON) solution/exploit_complete.py

# Run the student exploit stub
student-exploit:
	@echo "Running student exploit stub..."
	$(PYTHON) exploits/echo_oracle_stub.py

# Code coverage
coverage:
	@echo "Running tests with coverage..."
	$(PYTEST) tests/ --cov=src --cov-report=html --cov-report=term
	@echo "Coverage report in htmlcov/"

# Lint code
lint:
	@echo "Linting code..."
	flake8 src/ tests/ --max-line-length=100 --ignore=E501

# Clean up
clean:
	@echo "Cleaning up..."
	rm -rf __pycache__ */__pycache__ */*/__pycache__
	rm -rf .pytest_cache */.pytest_cache
	rm -rf htmlcov .coverage
	rm -rf *.bin diff_*.bin crash-* differential_*.json
	rm -rf fuzzing/harness/*.bin fuzzing/harness/diff_*
	rm -rf $(VENV)
	@echo "Clean complete"

# Deep clean (including corpus)
distclean: clean
	rm -rf fuzzing/corpus/seed_ciphertexts/*.bin
	rm -rf fuzzing/output

# Help
help:
	@echo ""
	@echo "Crystal Echo Lab - Available Targets"
	@echo "====================================="
	@echo ""
	@echo "  setup          - Create venv and install dependencies"
	@echo "  test           - Run basic tests"
	@echo "  test-all       - Run all tests"
	@echo "  corpus         - Generate fuzzing corpus"
	@echo "  fuzz           - Run differential fuzzer (default)"
	@echo "  fuzz-decaps    - Run decapsulation fuzzer"
	@echo "  fuzz-ciphertext - Run structure-aware fuzzer"
	@echo "  fuzz-diff      - Run differential fuzzer"
	@echo "  exploit        - Run solution exploit"
	@echo "  student-exploit - Run student exploit stub"
	@echo "  coverage       - Run tests with coverage"
	@echo "  lint           - Lint code"
	@echo "  clean          - Clean temp files"
	@echo "  distclean      - Deep clean including corpus"
	@echo ""
	@echo "Quick Start:"
	@echo "  make setup"
	@echo "  source venv/bin/activate"
	@echo "  make test"
	@echo "  make corpus"
	@echo "  make fuzz"
	@echo ""
