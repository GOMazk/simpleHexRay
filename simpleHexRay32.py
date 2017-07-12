#IDAPython
#simpleHexRay for 32bit code
from idautils import *

#1register 2segment 3pointer 4lea/arg 5integer/offset 7function/jmpdest

##get info of fuction
cursor=here()
funcname=GetFunctionName(cursor)
start=LocByName(funcname)
end=FindFuncEnd(cursor)
print "%s: %x-%x\n"%(funcname,start,end)


##read all bytes
hexcode=""
cursor = start
while cursor < end:
    hexcode = hexcode + "%02x"%Byte(cursor)
    cursor = cursor + 1


##skip known_prologue
known_prologue=["8d4c240483e4f0ff71fc5589e551"
                ,"5589e5"]
is_prologue=0
for pro in known_prologue: 
    if(hexcode[:len(pro)]==pro):
        is_prologue=1
        start = start + len(pro)/2
        break
if is_prologue==0:
    print "failed to find prologue\n\n"


##read lines into all_line
all_line=[]
cursor = start
while NextHead(cursor,end+1)!= BADADDR:
    mnem=GetMnem(cursor)
    op1_type=GetOpType(cursor,0)
    op1=GetOpnd(cursor,0)
    op2_type=GetOpType(cursor,1)
    op2=GetOpnd(cursor,1)
    print (mnem,op1_type,op1,op2_type,op2)
    line=[]
    line.append(mnem)
    line.append(op1_type)
    line.append(op1)
    line.append(op2_type)
    line.append(op2)
    line.append(cursor)
    all_line.append(line)

    cursor = NextHead(cursor,end)
#print all_line


registers={ #virtual registers except ebp,esp
    'eax':'eax'
    ,'ebx':'ebx'
    ,'ecx':'ecx'
    ,'edx':'edx'
    ,'esi':'esi'
    ,'edi':'edi'
    ,'al':'al'
}
compare="" #instead jump flags, store operation
params=[] #store pushed things
blockends=[] #store where to put '}'


def oper(line,op2,char): 
    if(line[1]==1):
#        print "(%s = %s %s %s)"%(line[2],registers[line[2]],char,op2)
        op1=registers[line[2]]
        registers[line[2]]="%s %s %s"%(registers[line[2]],char,op2)
    else:
        op1=line[2]
        print "%s = %s %s %s;"%(line[2],line[2],char,op2)
    return "%s %s (%s)"%(op1,char,op2) #return is string for compare


##converting start
print 'int %s{'%funcname
for line in all_line:
    if(line[5] in blockends):
        print '}'
    
    ##setting operands
    if(line[1]==3): #pointer
        line[2]= line[2].replace('[','') #need rework
        line[2]= line[2].replace(']','')
        line[2]= "*(%s)"%line[2] 
    if(line[3]==3):
        line[4]= line[4].replace('[','')
        line[4]= line[4].replace(']','')
        line[4]= "*(%s)"%line[4]
        
    if(line[1]==4): #local variables renaming / lea oprand
        line[2]=line[2].replace('[ebp+var_','v') #need rework
        line[2]=line[2].replace('dword ptr [ebp-','v')
        line[2]=line[2].replace('[','')
        line[2]=line[2].replace('h]','')
        line[2]=line[2].replace(']','')
        if(line[0]=='lea'):
            line[2]=line[2].replace('v','&v')
    if(line[3]==4):
        line[4]=line[4].replace('[ebp+var_','v')
        line[4]=line[4].replace('dword ptr [ebp-','v')
        line[4]=line[4].replace('[','')
        line[4]=line[4].replace('h]','')
        line[4]=line[4].replace(']','')
        if(line[0]=='lea'):
            line[4]=line[4].replace('v','&v')
    
    if(line[2]=='ebp' or line[2]=='esp'):#ignore when ebp,esp is in arg1
        continue

    op2=line[4] #if operand2 is register, load it to op2
    for reg in registers.keys():
        op2=op2.replace(reg,registers[reg])

    ##
    if(line[0]=='mov' or line[0]=='movzx' or line[0]=='lea'):
        if(line[1]==1):
#            print "(%s = %s)"%(line[2],op2)
            registers[line[2]]=op2
        else:
            print "%s = %s;"%(line[2],op2)


    elif(line[0]=='not'):
        if(line[1]==1):
#            print "(not %s)"%line[2]
            registers[line[2]]="~(%s)"%registers[line[2]]
        else:
            print "not %s;"%line[2]        

    elif(line[0]=='or'):
        compare = oper(line,op2,'|')
    elif(line[0]=='and'):
        compare = oper(line,op2,'&')
    elif(line[0]=='add'):
        compare = oper(line,op2,'+')
    elif(line[0]=='sub'):
        compare = oper(line,op2,'-')
        
    elif(line[0]=='xor'):
        if(line[2]==line[4]): #xor same,same => same=0
            if(line[1]==1):
#                print "xor(%s = 0)"%line[2]
                registers[line[2]] = '0'
            else:
                print "%s = 0;"%line[2]
            compare= "0"
        else:
            compare= oper(line,op2,'^')
            
    elif(line[0]=='push'):
        if(line[1]==1):
            op1= registers[line[2]]
        elif(line[1]==5 and type(GetString(GetOperandValue(line[5],0),-1,0))==str):
            op1= '\"' + GetString(GetOperandValue(line[5],0),-1,0).replace('\x0A','\\n') + '\"'
        else:
            op1= line[2]
        params.append(op1)

    elif(line[0]=='call'):
        string = "%s( "%(line[2])
        params.reverse()
        for param in params:
            string = string + "%s,"%param
        string = string[:-1]+" );"
        print string
        params=[]

    elif(line[0]=='cmp'):
        if(line[1]==1):
            op1= registers[line[2]]
        else:
            op1= line[2]
        if(op1 == op2):
            compare = "0"
        else:
            compare = "%s - %s"%(op1,op2)
    elif(line[0]=='test'):
        if(line[1]==1):
            op1= registers[line[2]]
        else:
            op1= line[2]
        if(op1 == op2):
            compare = "%s"%op1
        else:
            compare= "%s & %s"%(op1,op2)

    elif(line[0]=='setz'):
        if(line[1]==1):
#            print("(%s = (%s==0) )"%(registers[line[2]],compare) )
            registers[line[2]]= "!(%s)"%compare
    elif(line[0]=='jz'):
        print "if( %s != 0 ){"%compare
        blockends.append( GetOperandValue(line[5],0) )

    elif(line[0]=='leave'):
        continue #do nothing
    elif(line[0]=='retn'):
        print "return %s;"%(registers['eax'])
        
    else:
        print line
print '}'
