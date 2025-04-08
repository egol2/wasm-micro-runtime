(module $array-wasm.wasm
  (type (;0;) (func (param i32 i32) (result i32)))
  (type (;1;) (func (param i32 i32 i32 i64) (result i32)))
  (type (;2;) (func))
  (type (;3;) (func (param i32) (result i32)))
  (import "env" "bpf_map_lookup_elem" (func $bpf_map_lookup_elem (;0;) (type 0)))
  (import "env" "bpf_map_update_elem" (func $bpf_map_update_elem (;1;) (type 1)))
  (func $__wasm_call_ctors (;2;) (type 2))
  (func $array (;3;) (type 3) (param i32) (result i32)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    i32.const 0
    local.set 2
    local.get 1
    i32.const 0
    i32.store offset=12
    block ;; label = @1
      block ;; label = @2
        i32.const 1024
        local.get 1
        i32.const 12
        i32.add
        call $bpf_map_lookup_elem
        local.tee 3
        br_if 0 (;@2;)
        i32.const -1
        local.set 2
        br 1 (;@1;)
      end
      local.get 1
      local.get 3
      i32.load
      i32.const 1
      i32.add
      i32.store offset=8
      i32.const 1024
      local.get 1
      i32.const 12
      i32.add
      local.get 1
      i32.const 8
      i32.add
      i64.const 0
      call $bpf_map_update_elem
      drop
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 2
  )
  (memory (;0;) 2)
  (global $__stack_pointer (;0;) (mut i32) i32.const 66560)
  (global (;1;) i32 i32.const 1024)
  (global (;2;) i32 i32.const 1024)
  (global (;3;) i32 i32.const 1024)
  (global (;4;) i32 i32.const 1024)
  (global (;5;) i32 i32.const 66560)
  (global (;6;) i32 i32.const 1024)
  (global (;7;) i32 i32.const 66560)
  (global (;8;) i32 i32.const 131072)
  (global (;9;) i32 i32.const 0)
  (global (;10;) i32 i32.const 1)
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "array" (func $array))
  (export "ar" (global 1))
  (export "__dso_handle" (global 2))
  (export "__data_end" (global 3))
  (export "__stack_low" (global 4))
  (export "__stack_high" (global 5))
  (export "__global_base" (global 6))
  (export "__heap_base" (global 7))
  (export "__heap_end" (global 8))
  (export "__memory_base" (global 9))
  (export "__table_base" (global 10))
  (@producers
    (processed-by "clang" "19.1.5-wasi-sdk (https://github.com/llvm/llvm-project ab4b5a2db582958af1ee308a790cfdb42bd24720)")
  )
  (@custom "target_features" (after code) "\04+\0amultivalue+\0fmutable-globals+\0freference-types+\08sign-ext")
)
