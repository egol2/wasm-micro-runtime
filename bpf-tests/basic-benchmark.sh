#!/usr/bin/env bash
# This script runs the commands 20 times and outputs CSV formatted results.
# CSV columns: Iteration,WASM_Total_ns,WASM_Avg_ns,eBPF_Total_ns,eBPF_Avg_ns,C_Total_ns,C_Avg_ns

echo "Iteration,WASM_Total_ns,WASM_Avg_ns,eBPF_Total_ns,eBPF_Avg_ns,C_Total_ns,C_Avg_ns"

for i in {1..20}; do
    # Run WASM benchmark
    wasm_out=$(./binary-funct-writer-wasm.o array-aot.o 1000000000)
    # Run eBPF benchmark
    ebpf_out=$(./binary-func-writer.o non-inlined-bpf-array.o 1000000000)
    # Run C benchmark
    c_out=$(./c-binary-rewriter.o array-c.o 1000000000)

    # Parse WASM timings
    wasm_line=$(echo "$wasm_out" | awk '/WASM execution time:/ {getline; print}')
    wasm_tot=$(echo "$wasm_line" | sed -n 's/.*took: \([0-9]*\) ns total.*/\1/p')
    wasm_avg=$(echo "$wasm_line" | sed -n 's/.*Average time: \([0-9.]*\) ns.*/\1/p')

    # Parse eBPF timings
    ebpf_line=$(echo "$ebpf_out" | awk '/eBPF execution time:/ {getline; print}')
    ebpf_tot=$(echo "$ebpf_line" | sed -n 's/.*took: \([0-9]*\) ns total.*/\1/p')
    ebpf_avg=$(echo "$ebpf_line" | sed -n 's/.*Average time: \([0-9.]*\) ns.*/\1/p')

    # Parse C timings
    c_line=$(echo "$c_out" | grep 'C execution:')
    c_tot=$(echo "$c_line" | sed -n 's/.*, \([0-9]*\) ns total.*/\1/p')
    c_avg=$(echo "$c_line" | sed -n 's/.*, \([0-9.]*\) ns av.*/\1/p')

    # Output CSV line
    echo "$i,$wasm_tot,$wasm_avg,$ebpf_tot,$ebpf_avg,$c_tot,$c_avg"
done
