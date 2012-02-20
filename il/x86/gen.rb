#!/usr/bin/env ruby

def putd(s)
  $stdout.puts(s)
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
  attr_reader :isoutput
  def initialize(name, isoutput = false)
    @name = name
    @isoutput = isoutput
  end
  def to_s
    @name
  end
  def ReilOperand.gen(s)
    puts(s)
  end
end

class ReilReg < ReilOperand
  def assign_operand(opnd)
    "assign_operand_register(#{opnd}, &#{@name})"
  end
  def ReilReg.from(native_opnd, blk)
    putd("trying to get a #{self.name} from #{native_opnd}")
    blk.decls << "reil_register reg;"
    if native_opnd.is_a?(NativeReg)
      blk.stmts << "get_reil_reg_from_x86_op(ctx, &x86_insn->#{native_opnd.op}, &reg);"
    elsif native_opnd.is_a?(NativeMem)
      gen("get_reil_reg_for_op()")	# XXX
    elsif native_opnd.is_a?(NativeImm)
      gen("get_reil_int_from_x86_op()")
      gen("gen_mov_int_reg()")
    else
      raise "can't get here"
    end
    putd("SUCCESS")
    ReilReg.new("reg")
  end
end

class ReilMem < ReilOperand
  def assign_opnd(opnd)
    raise "TBD"
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
  def assign_opnd(opnd)
    raise "TBD"
  end
  def ReilImm.from(native_opnd, blk)
    putd("trying to get a #{self.name} from #{native_opnd}")
    if native_opnd.is_a?(NativeReg)
      raise "can't get here"
    elsif native_opnd.is_a?(NativeMem)
      raise "can't get here"
    elsif native_opnd.is_a?(NativeImm)
      raise "TBD"
    else
      raise "can't get here"
    end
  end
end

class ReilInstruction
  @opnd_types
  def initialize(op1, op2, op3)
    @op1 = op1
    @op2 = op2
    @op3 = op3
    @body = ""
  end
  def to_s
    "#{@pre}#{self.class.name.downcase} #{@op1} #{@op2} #{@op3}"
  end
  def guards(blk, op1typ, op2typ)
    blk.stmts << "if (x86_insn->op1.type == #{op1typ.libdasm_optype} && x86_insn->op2.type == #{op1typ.libdasm_optype})"
  end
  def instantiate(pblk, op1typ, op2typ)
    guards(pblk, op1typ, op2typ)
    pblk.child { |blk|
      putd("@op1 = #{@op1}")
      nop1 = nop2 = nil
      if @op1 and @op1.is_a?(NativeOperand)
        # ok, assume op1 is actually of type op1typ,
        # and try to get a type we accept
        op1 = op1typ.new(@op1.op)
        @opnd_types[0].each { |typ|
          putd("trying to get #{typ} for op1")
          begin
            nop1 = typ.from(op1, blk)
            break if nop1	# first match wins
          rescue Exception => e
            putd("Failed: #{e}")
          end
        }
        if !nop1
          pute("can't get a reil operand from #{op1typ}")
          exit(3)
        end
      end
      if @op2 and @op2.is_a?(NativeOperand)
        @opnd_types[1].each { |typ|
          putd("trying to get #{typ} for op2")
          begin
            nop2 = typ.from(op2typ.new(@op2.op))
            break if nop2	# first match wins
          rescue Exception => e
            putd("Failed: #{e}")
          end
        }
        if !nop2
          pute("can't get a reil operand from #{op2typ}")
          exit(3)
        end
      end
      blk.decls << "reil_instruction insn;"
      blk.stmts << "insn = alloc_reil_instruction(ctx, REIL_#{self.class.name.upcase});"
      if nop1
        blk.stmts << nop1.assign_operand(@op1.op)
      end
      if nop2
        blk.stmts << nop2.assign_operand(@op2.op)
      end
    }
  end
end

class Add < ReilInstruction
  def initialize(op1, op2, op3)
    super(op1, op2, op3)
    @opnd_types = [[ReilReg.new, ReilImm.new], [ReilReg.new, ReilImm.new], [ReilReg.new(true)]]
  end
end

class Str < ReilInstruction
  def initialize(op1, op2, op3)
    super(op1, op2, op3)
    @opnd_types = [[ReilReg, ReilImm], [], [ReilReg]]
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
  @opnds
  attr_accessor :opnd_types
  def initialize(name)
    @name = name
    @opnd_types = []
    @template = nil
    @cfw = CFuncWriter.new("static void gen_#{name}_instr(translation_context *ctx)\n")
    @cfw.currblk.decls << "INSTRUCTION *x86_insn = ctx->x86instruction;\n"
  end
  def opnd_permutations
    @opnd_types[0].each { |op1|
      @opnd_types[1].each { |op2|
        if (op1 != NativeReg) or (op2 != NativeReg)
          next
        end
        yield op1, op2
      }
    }
  end
  def instantiate
    opnd_permutations { |op1, op2|
      @template.each { |reilop|
        reilop.instantiate(@cfw.currblk, op1, op2)
      }
    }
    puts(@cfw)
  end
end

class Mov < NativeInstruction
  def initialize(name)
    super(name)
    @opnd_types = [[NativeReg, NativeMem, NativeImm], [NativeReg, NativeMem, NativeImm]]
    @template = [
                 Str.new(NativeOperand.new("op1"), nil, NativeOperand.new("op2"))
                ]
  end
end

  

mov = Mov.new("mov")
mov.instantiate
