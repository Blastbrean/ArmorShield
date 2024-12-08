mod inline_constants;

extern crate libc;
use std::{ffi::{CStr, CString}, path::PathBuf, ptr::null};
use inline_constants::InlineConstants;
use base64::{prelude::BASE64_STANDARD, Engine};
use darklua_core::{generator::{LuaGenerator, ReadableLuaGenerator}, rules::{ComputeExpression, ContextBuilder, ConvertIndexToField, ConvertLocalFunctionToAssign, FlawlessRule, GroupLocalAssignment, RemoveComments, RemoveFunctionCallParens, RenameVariables}, Parser, Resources};

#[no_mangle]
pub extern "C" fn preprocess(loader: *const libc::c_char, source: *const libc::c_char, salt: *const libc::c_char, point: *const libc::c_char, id: *const libc::c_char) -> *const libc::c_char {
    let buf_source = unsafe { CStr::from_ptr(source).to_bytes() };
    let str_source = String::from_utf8(buf_source.to_vec()).unwrap();

    let buf_loader = unsafe { CStr::from_ptr(loader).to_bytes() };
    let str_loader = String::from_utf8(buf_loader.to_vec()).unwrap();

    let buf_salt = unsafe { CStr::from_ptr(salt).to_bytes() };
    let str_salt = String::from_utf8(buf_salt.to_vec()).unwrap();

    let buf_point = unsafe { CStr::from_ptr(point).to_bytes() };
    let str_point = String::from_utf8(buf_point.to_vec()).unwrap();

    let buf_id = unsafe { CStr::from_ptr(id).to_bytes() };
    let str_id = String::from_utf8(buf_id.to_vec()).unwrap();

    let salt = BASE64_STANDARD.decode(str_salt).unwrap();
    let point = BASE64_STANDARD.decode(str_point).unwrap();
    
    let parser = Parser::default();
    let source_block = match parser.parse(&str_source) {
        Ok(block) => block,
        Err(_) => {
            return null();
        }
    };

    let mut loader_block = match parser.parse(&str_loader) {
        Ok(block) => block,
        Err(_) => {
            return null();
        }
    };

    let resources = Resources::from_memory();
    let context = ContextBuilder::new(PathBuf::new(), &resources, str_loader.as_str()).build();
    InlineConstants::new(source_block, salt, point, str_id).flawless_process(&mut loader_block, &context);
    RemoveComments::default().flawless_process(&mut loader_block, &context);
    ConvertIndexToField::default().flawless_process(&mut loader_block, &context);
    ConvertLocalFunctionToAssign::default().flawless_process(&mut loader_block, &context);
    GroupLocalAssignment::default().flawless_process(&mut loader_block, &context);
    RemoveFunctionCallParens::default().flawless_process(&mut loader_block, &context);
    ComputeExpression::default().flawless_process(&mut loader_block, &context);
    RenameVariables::default().flawless_process(&mut loader_block, &context);

    let mut generator = ReadableLuaGenerator::new(usize::MAX);
    generator.write_block(&loader_block);
    
        
    let watermark = "-- Protected by ArmorShield <3 Blastbrean\n";
    let notice = "-- This script must be put inside of Luraph or Luarmor for real-world use.\n";
    let output = format!("{}{}{}", watermark, notice, generator.into_string());

    CString::new(output).unwrap().into_raw()
}