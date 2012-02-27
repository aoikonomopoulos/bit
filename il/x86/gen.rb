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

class ToBeDoneException < Exception
end

class CantHappenException < Exception
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
      hard = native_opnd.hard
      if hard
        blk.stmts << "#{r.name}.index = X86_REG_#{hard.name.upcase};"
        blk.stmts << "#{r.name}.size = #{hard.size};"
      else
        blk.stmts << "get_reil_reg_from_x86_op(ctx, &x86_insn->#{native_opnd.op}, &#{r.name});"
      end
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
      hard = native_opnd.hard
      if hard
        blk.stmts << "#{r.name}.index = X86_REG_#{hard.name.upcase};"
        blk.stmts << "#{r.name}.size = #{hard.size};"
      else
        blk.stmts << "get_reil_reg_from_x86_op(ctx, &x86_insn->#{native_opnd.op}, &#{r.name});"
      end
      return r
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
    else
      raise "can't get here"
    end
    putd("SUCCESS")
    r
  end
end

class ReilMem < ReilOperand
  def ReilMem.to(native_opnd, blk, stmts)
    putd("trying to get a #{native_opnd} from #{self.name}")
    if native_opnd.is_a?(NativeReg)
      raise "this seems unlikely, did something wrong?"
    elsif native_opnd.is_a?(NativeMem)
      raise ToBeDoneException
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
  def ReilImm.to(native_opnd, blk, stmts)
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

class Sizeof
  def initialize(opnd)
    @opnd = opnd
  end
  def expand(blk)
    if @opnd.instance_of?(NativeReg)
      i = ReilImm.new_tmp(blk)
      blk.stmts << "#{i.name}.size = 1;"
      blk.stmts << "#{i.name}.value = get_x86operand_size(x86_insn, &x86_insn->#{@opnd.op});"
      i
    else
      throw ToBeDoneException.new("sizeof(#{@opnd.class})")
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

  def native_cast(opnd, op1typ, op2typ)
    if opnd_is_specific(opnd)
      # this operand already has a specific type
      return opnd
    end
    # pretend the operand has the type we are assumming in this
    # instantiation
    if !opnd.instance_of?(NativeOperand)
      raise CantHappenException.new("unexpected type: #{opnd.class}")
    end
    native_type = [op1typ, op2typ][native_opnd_number(opnd.op) - 1]
    native_type.new(opnd.op)
  end

  def opnd_is_specific(opnd)
    opnd.is_a?(NativeReg) or opnd.is_a?(NativeMem) or opnd.is_a?(NativeImm)
  end

  def map_input_specific(accepted_types, op, blk)
    reil_op = nil
    accepted_types.each { |typ|
      begin
        reil_op = typ.from(op, blk)
        break if reil_op	# first match wins
      rescue Exception => e	# XXX: specific exception types
        putd("Failed: #{e}")
      end
    }
    if !reil_op
      pute("can't get a reil operand for input opnd of type #{op.class}")
      exit(3)
    end
    reil_op
  end
  def map_output_specific(accepted_types, op, blk, stmts)
    reil_op = nil
    accepted_types.each { |typ|
      begin
        putd("trying to get #{typ} for output opnd #{op}")
        reil_op = typ.to(op, blk, stmts)
        break if reil_op
      rescue Exception => e	# XXX: specific exception types
        putd("Failed to map output: #{e}")
      end
    }
    if !reil_op
      pute("can't get a reil operand for output opnd of type #{op.class}")
      exit(3)
    end
    reil_op
  end
  def map_input(opnd, opnd_types, blk)
    reil_op = nil
    if opnd.is_a?(NativeOperand)
      # opnd is already specific at this point
      raise CantHappenException if opnd.instance_of?(NativeOperand)
      reil_op = map_input_specific(opnd_types, opnd, blk)
    elsif opnd.instance_of?(Sizeof)
      reil_op = opnd.expand(blk)
    else
      raise CantHappenException.new("unknown input type: #{opnd.class}")
    end
    reil_op
  end

  # OK, this instruction is part of the expansion of a native instruction
  # to REIL instructions. If none of our operands are operands of the native
  # insn, we're in the clear. If some are, then we need to a) reference them
  # b) make sure that the constraints of this REIL instruction are satisfied.
  #
  # In this invocation, we assume that the native instruction's operand
  # types are the ones given, i.e. op1typ and op2typ. We will be called
  # for every valid operand type combination.
  def instantiate(pblk, op1typ, op2typ)
    putd("instantiating #{self} for op1:#{op1typ}, op2:#{op2typ}")
    pblk.child { |blk|
      reil_op1 = reil_op2 = nil
      # Map a native instruction operand to a REIL operand
      # The native_opnd is assumed to be of native_type. It needs to somehow
      # be transformed to one of the accepted types
      if @op1
        if @op1.is_a?(NativeOperand)
          op = native_cast(@op1, op1typ, op2typ)
        else
          op = @op1
        end
        reil_op1 = map_input(op, @opnd_types[0], blk)
      end
      if @op2
        if @op2.is_a?(NativeOperand)
          op = native_cast(@op2, op1typ, op2typ)
        else
          op = @op2
        end
        reil_op2 = map_input(op, @opnd_types[1], blk)
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
      if @op3
        if @op3.is_a?(NativeOperand)
          op = native_cast(@op3, op1typ, op2typ)
          reil_op3 = map_output_specific(@opnd_types[2], op, blk, post_stmts)
        else
          throw CantHappenException.new("unknown output type: #{@op3.class}")
        end
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

class Ldm < ReilInstruction
  def initialize(op1, op2, op3)
    super(op1, op2, op3)
    @opnd_types = [[ReilReg, ReilMem], [], [ReilReg]]
  end
end

class Stm < ReilInstruction
  def initialize(op1, op2, op3)
    super(op1, op2, op3)
    @opnd_types = [[ReilReg], [], [ReilReg]]
  end
end

class Str < ReilInstruction
  def initialize(op1, op2, op3)
    super(op1, op2, op3)
    @opnd_types = [[ReilImm, ReilReg], [], [ReilReg]]
  end
end

class Sub < ReilInstruction
  def initialize(op1, op2, op3)
    super(op1, op2, op3)
    @opnd_types = [[ReilImm, ReilReg], [ReilImm, ReilReg], [ReilReg]]
  end
end

class NativeOperand
  attr_reader :op
  def initialize(op)
    @op = op
  end
  def NativeOperand.mnemonic
    "o"
  end
end

class HardReg
  attr_reader :name, :size
  def initialize(n, sz)
    @name = n
    @size = sz
  end
end

class NativeReg < NativeOperand
  @@hard_regs = {}
  ["esp", "eax", "ebx", "ecx", "edx", "ebp", "eip"].each { |r|
    @@hard_regs[r] = HardReg.new(r, 4)
  }
  ["ax", "bx", "cx", "dx"].each { |r|
    @@hard_regs[r] = HardReg.new(r, 2)
  }
  # TBD (XXX: this sucks)

  @@libdasm_optype = "OPERAND_TYPE_REGISTER"
  def NativeReg.libdasm_optype
    @@libdasm_optype
  end
  def hard
    @@hard_regs[@op]
  end
  def NativeReg.mnemonic
    "r"
  end
end
class NativeMem < NativeOperand
  @@libdasm_optype = "OPERAND_TYPE_MEMORY"
  def NativeMem.libdasm_optype
    @@libdasm_optype
  end
  def NativeMem.mnemonic
    "m"
  end
end
class NativeImm < NativeOperand
  @@libdasm_optype = "OPERAND_TYPE_IMMEDIATE"
  def NativeImm.libdasm_optype
    @@libdasm_optype
  end
  def NativeImm.mnemonic
    "i"
  end
end

class InsnPattern
  attr_reader :handler
  def initialize(base, opnd_types1, opnd_types2, template)
    @name = "#{base}_#{encode_types(opnd_types1)}_#{encode_types(opnd_types2)}"
    @opnd_types1 = opnd_types1
    @opnd_types2 = opnd_types2
    @template = template
    @handler = "gen_#{@name}_instr"
    @cfw = CFuncWriter.new("static void #{@handler}(translation_context *ctx)\n")
    @cfw.currblk.decls << "INSTRUCTION *x86_insn = ctx->x86instruction;\n"
  end
  def opnds_permute
    @opnd_types1.each { |op1|
      @opnd_types2.each { |op2|
        if (op2 != nil) and (op1 == NativeImm)
          next
        elsif ((op1 == NativeMem) and (op2 == NativeMem))
          next
        end
        yield op1, op2
      }
    }
  end
  def instantiate
    opnds_permute { |typ1, typ2|
      # We assume these native operand types for this instantiation,
      # emit conditional to that effect
      guards(@cfw.currblk, typ1, typ2)
      @cfw.currblk.child { |body|
        @template.each { |reilop|
          reilop.instantiate(body, typ1, typ2)
        }
      }
    }
  end
  def emit
    $options[:outfile].puts(@cfw)
  end
  def loose_guards
    s = "if (("
    s << [[1, @opnd_types1], [2, @opnd_types2]].collect { |pair|
      idx = pair[0]
      opnd_types = pair[1]
      opnd_types.collect { |t|
        if t != nil
          "(x86_insn->op#{idx}.type == #{libdasm_opnd_type(t)})"
        else
          "(x86_insn->op#{idx}.type == OPERAND_TYPE_NONE)"
        end
      }.join(" || ")
    }.join(") && (")
    s << "))"
  end
private
  def encode_types(types)
    types.collect { |t|
      if t
        t.mnemonic
      else
        "E"
      end
    }.join("")
  end
  def libdasm_opnd_type(typ)
    if typ
      return typ.libdasm_optype
    end
    "OPERAND_TYPE_NONE"
  end
  def guards(blk, op1typ, op2typ)
    blk.stmts << "if ((x86_insn->op1.type == #{libdasm_opnd_type(op1typ)}) && " +
      "(x86_insn->op2.type == #{libdasm_opnd_type(op2typ)}))"
  end
end

class NativeInstruction
  attr_accessor :opnd_types, :patterns, :libdasm_idx
  @@defined_instructions = []
  def initialize(name, libdasm_idx)
    @name = name
    @libdasm_idx = libdasm_idx
    @patterns = []
    @@defined_instructions << self
  end
  def NativeInstruction.emit_insns
    @@defined_instructions.each { |i|
      i.instantiate
      i.emit
    }
  end
  def NativeInstruction.emit_demux
    s = "static (void (*handlers[])(INSTRUCTION *)) = {\n"
    @@defined_instructions.each { |i|
      if (i.patterns.size == 1)
        s << "\t[#{i.libdasm_idx}] = #{i.patterns[0].handler},\n"
      end
    }
    s << "};\n"
    $options[:outfile].puts(s)
    cfw = CFuncWriter.new("static void insn_mux(INSTRUCTION *x86_insn)")
    cfw.currblk.child { |blk|
      blk.stmts << "if (handlers[x86_insn->type])"
      blk.stmts << "\thandlers[x86_insn->type](x86_insn);"
      @@defined_instructions.each { |i|
        next if i.patterns.size == 1
        i.patterns.each { |p|
          blk.stmts << p.loose_guards
          blk.stmts << "\t#{p.handler}(x86_insn);"
        }
      }
    }
    $options[:outfile].puts(cfw)
  end
  def pattern(opnd_types1, opnd_types2, tmpl)
    @patterns << InsnPattern.new("#{@name}", opnd_types1, opnd_types2, tmpl)
  end
  def instantiate
    @patterns.each { |p|
      p.instantiate
    }
  end
  def emit
    @patterns.each { |p|
      p.emit
    }
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

mov = NativeInstruction.new("mov", "INSTRUCTION_TYPE_MOV")
mov.pattern([NativeReg, NativeMem, NativeImm], [NativeReg, NativeMem, NativeImm],
            [
             Str.new(NativeOperand.new("op2"), nil, NativeOperand.new("op1"))
            ])

push = NativeInstruction.new("push", "INSTRUCTION_TYPE_PUSH")
push.pattern([NativeReg], [nil],
             [
              Sub.new(NativeReg.new("esp"), Sizeof.new(NativeReg.new("op1")),
                      NativeReg.new("esp")),
              Stm.new(NativeOperand.new("op1"), nil, NativeReg.new("esp"))
             ])

ret = NativeInstruction.new("ret", "INSTRUCTION_TYPE_RET")
ret.pattern([nil], [nil],
             [
              Ldm.new(NativeReg.new("esp"), nil, NativeReg.new("eip"))
             ])

NativeInstruction.emit_insns
NativeInstruction.emit_demux
