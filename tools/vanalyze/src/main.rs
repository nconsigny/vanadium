use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::read_to_string;

/// Represents a node in the call hierarchy tree.
struct Node {
    addr: u32,                     // Function address (PC where execution begins)
    count: u64,                    // Number of instructions executed in this context
    children: HashMap<u32, usize>, // Maps child addresses to their node indices
}

/// Manages the tree of function calls.
struct Tree {
    nodes: Vec<Node>,
}

impl Tree {
    fn new() -> Self {
        Tree {
            nodes: vec![Node {
                addr: 0,
                count: 0,
                children: HashMap::new(),
            }],
        }
    }

    fn get_or_insert_child(&mut self, parent_idx: usize, addr: u32) -> usize {
        let parent = &self.nodes[parent_idx];
        if let Some(&child_idx) = parent.children.get(&addr) {
            child_idx
        } else {
            let child_idx = self.nodes.len();
            self.nodes.push(Node {
                addr,
                count: 0,
                children: HashMap::new(),
            });
            self.nodes[parent_idx].children.insert(addr, child_idx);
            child_idx
        }
    }

    fn compute_aggregate_counts(&self) -> HashMap<u32, u64> {
        let mut map = HashMap::new();
        for node in &self.nodes[1..] {
            // Skip root
            *map.entry(node.addr).or_insert(0) += node.count;
        }
        map
    }
}

/// Parsed RISC-V instruction.
enum Instruction {
    Regular,
    Jal { rd: u32, imm: i32 },
    Jalr { rd: u32, rs1: u32, imm: i32 },
}

fn parse_field<T: std::str::FromStr>(field: &str) -> Result<T, &'static str> {
    field
        .split(':')
        .nth(1)
        .ok_or("Missing field value")
        .and_then(|s| s.trim().parse::<T>().map_err(|_| "Failed to parse field"))
}

fn parse_instruction(s: &str) -> Result<Instruction, Box<dyn Error>> {
    if s.starts_with("Jal ") {
        let fields: Vec<&str> = s[4..]
            .trim_start_matches('{')
            .trim_end_matches('}')
            .split(',')
            .map(|f| f.trim())
            .collect();
        let rd: u32 = parse_field(fields.get(0).ok_or("Missing rd")?)?;
        let imm: i32 = parse_field(fields.get(1).ok_or("Missing imm")?)?;
        Ok(Instruction::Jal { rd, imm })
    } else if s.starts_with("Jalr ") {
        let fields: Vec<&str> = s[5..]
            .trim_start_matches('{')
            .trim_end_matches('}')
            .split(',')
            .map(|f| f.trim())
            .collect();
        let rd: u32 = parse_field(fields.get(0).ok_or("Missing rd")?)?;
        let rs1: u32 = parse_field(fields.get(1).ok_or("Missing rs1")?)?;
        let imm: i32 = parse_field(fields.get(2).ok_or("Missing imm")?)?;
        Ok(Instruction::Jalr { rd, rs1, imm })
    } else {
        Ok(Instruction::Regular)
    }
}

fn is_call(inst: &Instruction) -> bool {
    match inst {
        Instruction::Jal { rd, imm: _ } if *rd == 1 => true,
        Instruction::Jalr { rd, .. } if *rd == 1 => true,
        _ => false,
    }
}

fn is_return(inst: &Instruction) -> bool {
    match inst {
        Instruction::Jalr { rd, rs1, .. } if *rd == 0 && *rs1 == 1 => true,
        _ => false,
    }
}

fn print_node_html(tree: &Tree, node_idx: usize, parent_count: u64) -> String {
    let node = &tree.nodes[node_idx];
    let label = if node_idx == 0 {
        "root".to_string()
    } else {
        format!("{:x}", node.addr)
    };

    // Ratio of this node's inclusive count relative to its parent's inclusive count.
    let ratio = if parent_count == 0 {
        1.0
    } else {
        node.count as f64 / parent_count as f64
    };
    let pct = (ratio * 100.0).min(100.0);

    // Build summary line with a proportional bar and percentage.
    let mut html = format!(
        "<details><summary>{}: {} <span class=\"bar-container\"><span class=\"bar\" style=\"width:{:.2}%\"></span></span> ({:.1}%)</summary>\n",
        label,
        node.count,
        pct,
        pct
    );

    for &child_idx in node.children.values() {
        html += &print_node_html(tree, child_idx, node.count);
    }
    html += "</details>\n";
    html
}

fn generate_aggregate_html(aggregate: &HashMap<u32, u64>) -> String {
    let mut html =
        String::from("<h2>Aggregate Inclusive Instruction Counts per Function</h2>\n<table>\n");
    html += "<tr><th>Function Address</th><th>Count</th></tr>\n";
    let mut func_counts: Vec<(u32, u64)> = aggregate.iter().map(|(&k, &v)| (k, v)).collect();
    func_counts.sort_by(|a, b| b.1.cmp(&a.1));
    for (addr, count) in func_counts {
        html += &format!("<tr><td>{:x}</td><td>{}</td></tr>\n", addr, count);
    }
    html += "</table>\n";
    html
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <trace_file>", args[0]);
        std::process::exit(1);
    }

    let trace = read_to_string(&args[1])?;
    let lines: Vec<&str> = trace.lines().collect();

    let mut trace_data = Vec::new();
    for line in lines {
        let parts: Vec<&str> = line.split(" -> ").collect();
        if parts.len() != 2 {
            continue;
        }
        let pc_str = parts[0].split(": ").next().ok_or("Malformed trace line")?;
        if pc_str.len() < 8 {
            return Err("PC string too short".into());
        }
        let pc = u32::from_str_radix(&pc_str[pc_str.len() - 8..], 16)
            .map_err(|_| "Failed to parse PC")?;
        let decoded = parts[1];
        let inst = parse_instruction(decoded)?;
        trace_data.push((pc, inst));
    }

    let mut tree = Tree::new();
    let mut call_stack = vec![0];
    let mut trace_iter = trace_data.iter().peekable();

    while let Some(&(_, ref inst)) = trace_iter.next() {
        for &node_idx in &call_stack {
            tree.nodes[node_idx].count += 1;
        }
        if is_call(inst) {
            if let Some(&(target_pc, _)) = trace_iter.peek() {
                let current_node_idx = *call_stack.last().unwrap();
                let child_idx = tree.get_or_insert_child(current_node_idx, *target_pc);
                call_stack.push(child_idx);
            }
        } else if is_return(inst) {
            if call_stack.len() > 1 {
                call_stack.pop();
            }
        }
    }

    let call_hierarchy_html = print_node_html(&tree, 0, tree.nodes[0].count);
    let aggregate = tree.compute_aggregate_counts();
    let aggregate_html = generate_aggregate_html(&aggregate);

    let full_html = format!(
        r#"
        <html>
        <head>
        <title>RISC-V Execution Profile</title>
        <style>
        body {{ font-family: Arial, sans-serif; }}
        details {{ margin-left: 20px; }}
        summary {{ cursor: pointer; }}
        table {{ border-collapse: collapse; }}
        th, td {{ border: 1px solid black; padding: 5px; }}
        .bar-container {{ display:inline-block; width:240px; height:10px; background:#eee; margin-left:8px; vertical-align:middle; }}
        .bar {{ display:inline-block; height:100%; background:#4CAF50; }}
        summary {{ display:flex; align-items:center; gap:4px; }}
        </style>
        </head>
        <body>
        <h1>Call Hierarchy</h1>
        {}
        {}
        </body>
        </html>
        "#,
        call_hierarchy_html, aggregate_html
    );

    std::fs::write("output.html", full_html)?;
    println!("HTML output written to output.html");
    Ok(())
}
