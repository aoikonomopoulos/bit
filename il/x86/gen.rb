#!/usr/bin/env ruby

require 'optparse'

$options = {
  :outfile => $stdout,
  :debug => false,
}

def putd(s)
  if $options[:debug]
    $stdout.puts(s)
  end
end

def pute(s)
  $stderr.puts(s)
end

class DeclStatements < Array
  def initialize
    super(["{\n"])
  end
  def << (s, noindent=false)
    super("\t" + s)
  end
end

class BlockStatements < Array
  def << (s, noindent=false)
    super("\t" + s)
  end
  def close
    self[self.size] = "}\n"
  end
end

class CBlock
  attr_reader :decls, :stmts, :parent
  def initialize(parent = nil, indent_lvl = 0)
    @indent = indent_lvl
    @decls = DeclStatements.new
    @stmts = BlockStatements.new
  end
  def to_s
    "#{@decls.join("\n")}\n#{@stmts.join("\n")}"
  end
  def child
    c = CBlock.new(@indent + 1)
    yield c
    c.stmts.close
    c.decls.each { |d|
      @stmts << d
    }
    @stmts << ""
    c.stmts.each { |s|
      @stmts << s
    }
  end
end

class CFuncWriter
  attr_reader :currblk
  def initialize(definition)
    @definition = definition
    @currblk = CBlock.new(nil)
  end
  def to_s
    @currblk.stmts.close
    @definition + @currblk.to_s
  end
end

class ReilOperand
  attr_reader :name
  def initialize(name)
    @name = name
  end
  def to_s
    @name
  end
  def ReilOperand.gen(s)
    puts(s)
  end
end

class ReilReg < ReilOperand
  @@seq = 0
  def ReilReg.new_tmp(blk)
    r = ReilReg.new("t#{@@seq}")
    @@seq += 1
    blk.decls << "reil_register #{r.name};"
    r
  end
  def ReilReg.to(native_opnd, blk, stmts)
    if native_opnd.is_a?(NativeReg)
      r = ReilReg.new_tmp(blk)
      blk.stmts << "get_reil_reg_from_x86_op(ctx, &x86_insn->#{native_opnd.op}, &#{r.name});"
      return r
    elsif native_opnd.is_a?(NativeMem)
      r = ReilReg.new_tmp(blk)
      md = /\d+/.match(r.name)
      raise "internal error" unless md
      offset = "offset#{md[0]}"
      blk.decls << "memory_offset #{offset};"
      blk.stmts << "alloc_temp_reg(ctx, get_x86operand_size(x86_insn, &x86_insn->#{native_opnd.op}), &#{r.name});"
      blk.stmts << "calculate_memory_offset(ctx, &x86_insn->#{native_opnd.op}, &#{offset});"
      stmts << "if (#{offset}.type == REGISTER_OFFSET)"
      stmts << "\tgen_store_reg_reg(ctx, &#{r.name}, &#{offset}.reg);"
      stmts << "else"
      stmts << "\tgen_store_reg_int(ctx, &#{r.name}, &#{offset}.integer);"
      r
    elsif native_opnd.is_a?(NativeImm)
      raise "can't have immediate output operands"
    else
      raise "can't get here"
    end
  end
  def ReilReg.from(native_opnd, blk)
    putd("trying to get a #{self.name} from #{native_opnd}")
    if native_opnd.is_a?(NativeReg)
      r = ReilReg.new_tmp(blk)
      blk.stmts << "get_reil_reg_from_x86_op(ctx, &x86_insn->#{native_opnd.op}, &#{r.name});"
    elsif native_opnd.is_a?(NativeMem)
      r = ReilReg.new_tmp(blk)
      md = /\d+/.match(r.name)
      raise "internal error" unless md
      offset = "offset#{md[0]}"
      blk.decls << "memory_offset #{offset};"
      blk.stmts << "alloc_temp_reg(ctx, get_x86operand_size(x86_insn, &x86_insn->#{native_opnd.op}), &#{r.name});"
      blk.stmts << "calculate_memory_offset(ctx, &x86_insn->#{native_opnd.op}, &#{offset});"
      blk.stmts << "if (#{offset}.type == REGISTER_OFFSET)"
      blk.child { |cblk|
        cblk.stmts << "gen_load_reg_reg(ctx, &#{offset}.reg, &#{r.name});"
      }
      blk.stmts << "else"
      blk.child { |cblk|
        cblk.stmts << "gen_load_int_reg(ctx, &#{offset}.integer, &#{r.name});"
      }
    elsif native_opnd.is_a?(NativeImm)
      r = ReilReg.new_tmp(blk)
      md = /\d+/.match(r.name)
      raise "internal error" unless md
      integer = "integer#{md[0]}"
      blk.decls << "reil_integer #{integer};"
      blk.stmts << "alloc_temp_reg(ctx, get_x86operand_size(x86_insn, &x86_insn->#{native_opnd.op}), &#{r.name});"
      bkl.stmts << "get_reil_int_from_x86_op(ctx, &x86_insn->#{native_opend.op}, &#{integer});"
      blk.stmts << "gen_mov_int_reg(ctx, &#{integer}, &#{r.name});"
      gen("get_reil_int_from_x86_op()")
      gen("gen_mov_int_reg()")
    else
      raise "can't get here"
    end
    putd("SUCCESS")
    r
  end
end

class ReilMem < ReilOperand
  def ReilMem.to(native_opnd, blk)
    putd("trying to get a #{native_opnd} from #{self.name}")
    if native_opnd.is_a?(NativeReg)
      raise "this seems unlikely, did something wrong?"
    elsif native_opnd.is_a?(NativeMem)
      raise "TBD"
    elsif native_opnd.is_a?(NativeImm)
      raise "can't have immediate output operands"
    else
      raise "can't get here"
    end
  end
  def ReilMem.from(native_opnd, blk)
    putd("trying to get a #{self.name} from #{native_opnd}")
    if native_opnd.is_a?(NativeReg)
      raise "can't get here"
    elsif native_opnd.is_a?(NativeMem)
      raise "TBD"
      gen("get_reil_addr_from_op()")	# XXX
    elsif native_opnd.is_a?(NativeImm)
      raise "TBD"
    else
      raise "can't get here"
    end
  end
end

class ReilImm < ReilOperand
  @@seq = 0
  def ReilImm.new_tmp(blk)
    i = ReilImm.new("i#{@@seq}")
    @@seq += 1
    blk.decls << "reil_integer #{i.name};"
    i
  end
  def ReilImm.to(native_opnd, blk)
    raise "REIL can't have immediate outputs (duh)"
  end
  def ReilImm.from(native_opnd, blk)
    putd("trying to get a #{self.name} from #{native_opnd}")
    if native_opnd.is_a?(NativeReg)
      raise "can't get here"
    elsif native_opnd.is_a?(NativeMem)
      raise "can't get here"
    elsif native_opnd.is_a?(NativeImm)
      i = ReilImm.new_tmp(blk)
      blk.stmts << "get_reil_int_from_x86_op(ctx, &x86_insn->#{native_opnd.op}, &#{i.name});"
      return i
    else
      raise "can't get here"
    end
  end
end

class ReilInstruction
  @opnd_types
  @@seq = 0
  def initialize(op1, op2, op3)
    @op1 = op1
    @op2 = op2
    @op3 = op3
    @body = ""
  end
  def to_s
    "#{@pre}#{self.class.name.downcase} #{@op1} #{@op2} #{@op3}"
  end
  def ReilInstruction.newname
    @@seq += 1
    "insn#{@@seq}"
  end
  def guards(blk, op1typ, op2typ)
    blk.stmts << "if (x86_insn->op1.type == #{op1typ.libdasm_optype} && x86_insn->op2.type == #{op2typ.libdasm_optype})"
  end

  # Map a native instruction operand to a REIL operand
  # The native_opnd is assumed to be of native_type. It needs to somehow
  # be transformed to one of the accepted types
  def map_operand(accepted_types, native_opnd, native_type, blk)
    reil_op = nil
    # ok, assume our native operand is actually of type 'typ'
    # and try to get an operand of a type we accept
    op = native_type.new(native_opnd.op)
    accepted_types.each { |typ|
      putd("trying to get #{typ} for input opnd #{op}")
      begin
        reil_op = typ.from(op, blk)
        break if reil_op	# first match wins
      rescue Exception => e
        putd("Failed: #{e}")
      end
    }
    if !reil_op
      pute("can't get a reil operand for input opnd of type #{native_type}")
      exit(3)
    end
    reil_op
  end
  def map_output_operand(accepted_types, native_type, blk, stmts)
    reil_op = nil
    op = native_type.new(@op3.op)
    accepted_types.each { |typ|
      begin
        putd("trying to get #{typ} for output opnd #{op}")
        reil_op = typ.to(op, blk, stmts)
        break if reil_op
      rescue Exception => e
        putd("Failed to map output: #{e}")
      end
    }
    if !reil_op
      pute("can't get a reil operand for output opnd of type #{native_type}")
      exit(3)
    end
    reil_op
  end
  def native_opnd_number(name)
    md = /^op(\d)$/.match(name)
    raise "WTF, unexpected native operand name (#{name})" unless md
    md[1].to_i
  end
  def assign_operand(insn, idx, opnd)
    if opnd.is_a?(ReilReg)
      "assign_operand_register(&#{insn}->operands[#{idx}], &#{opnd.name});"
    elsif opnd.is_a?(ReilImm)
      "assign_operand_integer(&#{insn}->operands[#{idx}], &#{opnd.name});"
    else
      raise "internal error"
    end
  end
  # OK, this instruction is part of the expansion of a native instruction
  # to REIL instructions. If none of our operands are operands of the native
  # insn, we're in the clear. If some are, then we need to a) reference them
  # b) make sure that the constraints of this REIL instruction are satisfied.
  #
  # In this invocation, we must assume that the native instruction's operand
  # types are the ones given, i.e. op1typ and op2typ
  def instantiate(pblk, op1typ, op2typ)
    putd("instantiating #{self} for op1:#{op1typ}, op2:#{op2typ}")
    # We assume these native operand types here, emit conditional to that effect
    guards(pblk, op1typ, op2typ)
    # emit the body of the conditional statement above
    pblk.child { |blk|
      reil_op1 = reil_op2 = nil
      # is our first REIL operand a native operand?
      if @op1 and @op1.is_a?(NativeOperand)
        # if so, transform it to a REIL operand that satisfies our constraints
        reil_op1 = map_operand(@opnd_types[0], @op1, [op1typ, op2typ][native_opnd_number(@op1.op) - 1], blk)
      end
      if @op2 and @op2.is_a?(NativeOperand)
        reil_op2 = map_operand(@opnd_types[1], @op2, [op1typ, op2typ][native_opnd_number(@op2.op) - 1], blk)
      end
      insn_name = ReilInstruction.newname
      blk.decls << "reil_instruction *#{insn_name};"
      blk.stmts << "#{insn_name} = alloc_reil_instruction(ctx, REIL_#{self.class.name.upcase});"
      if reil_op1
        blk.stmts << assign_operand(insn_name, 0, reil_op1)
      end
      if reil_op2
        blk.stmts << assign_operand(insn_name, 1, reil_op2)
      end
      reil_op3 = nil
      post_stmts = []
      if @op3 and @op3.is_a?(NativeOperand)
        reil_op3 = map_output_operand(@opnd_types[2], [op1typ, op2typ][native_opnd_number(@op3.op) - 1], blk, post_stmts)
      end
      if reil_op3
        blk.stmts << assign_operand(insn_name, 2, reil_op3)
        post_stmts.each { |s|
          blk.stmts << s
        }
      end
    }
  end
end

class Add < ReilInstruction
  def initialize(op1, op2, op3)
    super(op1, op2, op3)
    @opnd_types = [[ReilImm, ReilReg], [ReilImm, ReilReg], [ReilReg]]
  end
end

class Str < ReilInstruction
  def initialize(op1, op2, op3)
    super(op1, op2, op3)
    @opnd_types = [[ReilImm, ReilReg], [], [ReilReg]]
  end
end

class NativeOperand
  attr_reader :op
  def initialize(op)
    @op = op
  end
end

class NativeReg < NativeOperand
  @@libdasm_optype = "OPERAND_TYPE_REGISTER"
  def NativeReg.libdasm_optype
    @@libdasm_optype
  end
end
class NativeMem < NativeOperand
  @@libdasm_optype = "OPERAND_TYPE_MEMORY"
  def NativeMem.libdasm_optype
    @@libdasm_optype
  end
end
class NativeImm < NativeOperand
  @@libdasm_optype = "OPERAND_TYPE_IMMEDIATE"
  def NativeImm.libdasm_optype
    @@libdasm_optype
  end
end

class NativeInstruction
  attr_accessor :opnd_types
  def initialize(name)
    @name = name
    @cfw = CFuncWriter.new("static void gen_#{name}_instr(translation_context *ctx)\n")
    @cfw.currblk.decls << "INSTRUCTION *x86_insn = ctx->x86instruction;\n"
  end
  def opnds_permute(opnd_types1, opnd_types2)
    opnd_types1.each { |op1|
      opnd_types2.each { |op2|
        if op1 == NativeImm
          next
        elsif ((op1 == NativeMem) and (op2 == NativeMem))
          next
        end
        yield op1, op2
      }
    }
  end
  def pattern(opnd_types1, opnd_types2, template)
    opnds_permute(opnd_types1, opnd_types2) { |op1, op2|
      template.each { |reilop|
        reilop.instantiate(@cfw.currblk, op1, op2)
      }
    }
  end
  def emit
    $options[:outfile].puts(@cfw)
  end
end

class Mov < NativeInstruction
  def initialize(name)
    super(name)
    @opnd_types = [[NativeReg, NativeMem, NativeImm], [NativeReg, NativeMem, NativeImm]]
    @template = [
                 Str.new(NativeOperand.new("op2"), nil, NativeOperand.new("op1"))
                ]
  end
end

optp = OptionParser.new { |opts|
  opts.on("-d", "--[no-]debug", "Produce debug output") { |d|
    $options[:debug] = d
  }
  opts.on("-o", "--output=PATH", "Emit to PATH") { |p|
    $options[:outfile] = File.open(p, "w+")
  }
}
optp.parse!

mov = NativeInstruction.new("mov")
mov.pattern([NativeReg, NativeMem, NativeImm], [NativeReg, NativeMem, NativeImm],
            [
             Str.new(NativeOperand.new("op2"), nil, NativeOperand.new("op1"))
            ])
mov.emit
