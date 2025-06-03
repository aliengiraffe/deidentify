#!/bin/bash

# Script to run benchmarks with profiling and generate reports
# Usage: ./scripts/profile-benchmarks.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Deidentify Benchmark Profiling ===${NC}"

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Change to project root
cd "$PROJECT_ROOT"

# Create profiles directory
mkdir -p profiles

echo -e "\n${YELLOW}Running benchmarks with CPU profiling...${NC}"
go test -bench=BenchmarkParagraphDeidentification -benchtime=1x -cpuprofile=profiles/cpu.prof -benchmem . > profiles/benchmark.txt 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}CPU profiling benchmark failed. Check profiles/benchmark.txt for errors.${NC}"
    cat profiles/benchmark.txt
    exit 1
fi

echo -e "\n${YELLOW}Running benchmarks with memory profiling...${NC}"
go test -bench=BenchmarkParagraphDeidentification -benchtime=1x -memprofile=profiles/mem.prof . >> profiles/benchmark.txt 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}Memory profiling benchmark failed. Check profiles/benchmark.txt for errors.${NC}"
    cat profiles/benchmark.txt
    exit 1
fi

echo -e "\n${YELLOW}Running parallel benchmarks...${NC}"
go test -bench=BenchmarkParagraphDeidentificationParallel -benchtime=10s . >> profiles/benchmark.txt 2>&1

echo -e "\n${GREEN}=== Benchmark Results ===${NC}"
cat profiles/benchmark.txt | grep -E "(Benchmark|Mean time|Throughput|ns/op|B/op|allocs/op)" || echo "No benchmark results found"

echo -e "\n${YELLOW}Generating CPU profile reports...${NC}"
go tool pprof -top -nodecount=20 profiles/cpu.prof > profiles/cpu_top20.txt
go tool pprof -text profiles/cpu.prof > profiles/cpu_text.txt
echo "CPU Top 20 saved to profiles/cpu_top20.txt"

echo -e "\n${YELLOW}Generating memory profile reports...${NC}"
go tool pprof -top -nodecount=20 profiles/mem.prof > profiles/mem_top20.txt
go tool pprof -text profiles/mem.prof > profiles/mem_text.txt
echo "Memory Top 20 saved to profiles/mem_top20.txt"

echo -e "\n${YELLOW}Generating focused deidentify reports...${NC}"
go tool pprof -focus=deidentify -text profiles/cpu.prof > profiles/cpu_deidentify_focused.txt
echo "Focused deidentify analysis saved to profiles/cpu_deidentify_focused.txt"

# Check if graphviz is installed for graph generation
if command -v dot &> /dev/null; then
    echo -e "\n${YELLOW}Generating visual graphs (SVG/PNG)...${NC}"
    go tool pprof -svg profiles/cpu.prof > profiles/cpu_graph.svg
    go tool pprof -png profiles/cpu.prof > profiles/cpu_graph.png
    go tool pprof -svg profiles/mem.prof > profiles/mem_graph.svg
    go tool pprof -png profiles/mem.prof > profiles/mem_graph.png
    go tool pprof -focus=deidentify -svg profiles/cpu.prof > profiles/cpu_deidentify_focused.svg
    echo "Visual graphs generated successfully"
else
    echo -e "\n${YELLOW}Graphviz not installed. Skipping visual graph generation.${NC}"
    echo "Install with: brew install graphviz (macOS) or apt-get install graphviz (Linux)"
fi

echo -e "\n${GREEN}=== Profile Analysis Commands ===${NC}"
echo "To analyze profiles interactively:"
echo "  go tool pprof profiles/cpu.prof"
echo "  go tool pprof profiles/mem.prof"
echo ""
echo "To start web UI (requires graphviz):"
echo "  go tool pprof -http=:8080 profiles/cpu.prof"
echo ""
echo "All reports saved in: ${PROJECT_ROOT}/profiles/"