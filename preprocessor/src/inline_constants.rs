use darklua_core::{nodes::{BinaryNumber, Block, Expression, FunctionExpression, LocalAssignStatement, NumberExpression, StringExpression, TableEntry, TableIndexEntry}, process::{DefaultVisitor, NodeProcessor, NodeVisitor}, rules::{Context, FlawlessRule}};

const SCRIPT_FUNCTIONS_TBL_IDENTIFIER: &str = "SCRIPT_FUNCTIONS";
const SALT_TBL_IDENTIFIER: &str = "DB_HDKF_SALT";
const POINT_TBL_IDENTIFIER: &str = "DB_CURVE_POINT";

#[derive(Debug)]
pub(crate) struct InlineConstantsProcessor {
    ic: InlineConstants,
}

impl InlineConstantsProcessor {
    pub fn new(ic: InlineConstants) -> Self {
        Self { ic }
    }
}

fn append_byte_table_entries(entries: &mut Vec<TableEntry>, bytes: &[u8]) {
    for byte in bytes {
        let expr = NumberExpression::Binary(BinaryNumber::new(*byte as u64, true));
        entries.push(TableEntry::Value(Expression::Number(expr)));
    }
}

impl NodeProcessor for InlineConstantsProcessor {
    fn process_local_assign_statement(&mut self, las: &mut LocalAssignStatement) {
        if las.values_len() != 1 {
            return
        }
        
        let las_copy = las.clone();
        let variables = las_copy.get_variables();

        let table = match las.iter_mut_values().next() {
            Some(Expression::Table(table)) => table,
            _ => return
        };
        let variable = match variables.get(0) {
            Some(variable) => variable,
            _ => return
        };
        
        let name = variable.get_identifier().get_name();
    
        if name == SALT_TBL_IDENTIFIER {
            append_byte_table_entries(table.mutate_entries(), &self.ic.salt)
        }

        if name == POINT_TBL_IDENTIFIER {
            append_byte_table_entries(table.mutate_entries(), &self.ic.point)
        }
    
        if name == SCRIPT_FUNCTIONS_TBL_IDENTIFIER {
            let func = FunctionExpression::new(self.ic.source.clone(), Vec::new(), true);
            table.mutate_entries().push(TableEntry::Index(TableIndexEntry::new(
                Expression::String(StringExpression::from_value(&self.ic.id.clone())),
                Expression::Function(func),
            )));
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InlineConstants {
    source: Block,
    salt: Vec<u8>,
    point: Vec<u8>,
    id: String,
}

impl InlineConstants {
    pub fn new(source: Block, salt: Vec<u8>, point: Vec<u8>, id: String) -> Self {
        Self { source, salt, point, id }
    }
}

impl FlawlessRule for InlineConstants {
    fn flawless_process(&self, block: &mut Block, _: &Context) {
        let mut processor = InlineConstantsProcessor::new(self.clone());
        DefaultVisitor::visit_block(block, &mut processor);
    }
}