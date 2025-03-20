Very simple tool to analyze a trace file as printed by the `trace` feature in the Vanadium VM app:

```
00016cb4: 00b14603 -> Lbu { rd: 12, rs1: 2, imm: 11 }
00016cb8: 00a14683 -> Lbu { rd: 13, rs1: 2, imm: 10 }
00016cbc: 00914703 -> Lbu { rd: 14, rs1: 2, imm: 9 }
00016cc0: 00b98a23 -> Sb { rs1: 19, rs2: 11, imm: 20 }
00016cc4: 00c989a3 -> Sb { rs1: 19, rs2: 12, imm: 19 }
00016cc8: 00d98923 -> Sb { rs1: 19, rs2: 13, imm: 18 }
00016ccc: 00e988a3 -> Sb { rs1: 19, rs2: 14, imm: 17 }
00016cd0: 008ad593 -> Srli { rd: 11, rs1: 21, imm: 8 }
00016cd4: 00b98323 -> Sb { rs1: 19, rs2: 11, imm: 6 }
00016cd8: 015982a3 -> Sb { rs1: 19, rs2: 21, imm: 5 }
```

and produce a report of the number of execution steps that were spent inside each function.

It uses `Jal` and `Jalr` opcodes as the heuristic to identify calls and call returns, therefore reconstructing a hierarchical call stack.

Usage:

```
$ cargo run trace.txt
```

It will produce an html file called `output.html`.