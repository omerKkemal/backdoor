import os

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

def clear():
    os.system("clear")

def code(script):
    for i, code in enumerate(script):
        print(f"[{i}] {code}")


def write_to_file(codes):
    with open("code.py", "a") as f:
        for code in codes:
            f.write(code + "\n")


def search(find,script):

    b = 0
    for k,line in enumerate(script):
        if find in line:
            for i,f_letter in enumerate(line):
                if find[0] == f_letter and find == line[i:len(find) + i]:
                    print(f'{GREEN}{line}{END}')
                        

        else:
            print(f"[{k}] {line}")

def Help():
    print("""
                     _____________________________________________
                     [.::::::::::::::::Help:::::::::::::::::::::.]
                     _____________________________________________

            ______________________________________________________________
            [ comands .....................  descriptions                ]
            [ -------                        ------------                ]
            [ :h  .........................  ptint this help message     ]
            [ :q  .........................  Exit from the program       ]
            [                                without saving              ]
            [ :w  .........................  write to a file             ]
            [                                with deffult file name      ]
            [ :ex .........................  it used to excuet           ]
            [                                the code befor saving       ]
            [ :re .........................  it used to replace          ]
            [                                a single line with it index ]
            [ :f  .........................  it used to find specific str]
            ______________________________________________________________

    """)
    input("[Press_Enter_To_Continue]")
def Menu():
    menu = """
        ____________________________________________________________________
        [   Note that : if you create code.py.                             ]
        [               please include main function in your  code.        ]
        [               which handles all the code instructions.           ]
        [            .::::::::Menu:::::::::.                               ]
        [            [C] creat code.py file                                ]
        [            [R] Run the code.py                                   ]
        [            [H] Help                                              ]
        [            [E] Exit                                              ]
        ____________________________________________________________________"""
    return menu

def edit():
    script = []
    com_mode = ":"
    i = 0
    while True:
        line = input(f"[{i}] ")
        i += 1
        if line[0] == com_mode:
            coms = line.split(" ")
            com = coms[0][1:]
            if len(coms) == 1:
                if com == "w":
                    write_to_file(script)
                elif com == "ex":
                    clear()
                    n="\n"

                    print("""
                        <---*---*---[Output]---*---*--->
                    """)
                    exec(n.join(script))
                    print(f"""
                        <---*---*---[ Code.py ]---*---*--->
                    """)
                    code(script)
                    i = len(script)
                elif com == "q":
                    clear()
                    break
                elif com == "h":
                    clear()
                    Help()
                    clear()
                    code(script)
                    i = len(script)
                    print(f"""
                        <---*---*---[ Code.py ]---*---*--->
                    """)

            else:
                if com == "re":
                    find = coms[1]
                    replace = " ".join(coms[2:])
                    #print(replace)
                    script[int(find)] = replace
                    clear()
                    print(f"""
                        <---*---*---[ Code.py ]---*---*--->
                    """)
                    code(script)
                    i = len(script)
                elif com == "f":
                    find = " ".join(coms[1:])
                    clear()
                    print(f"""
                        <---*---*---[ Code.py ]---*---*--->
                    """)
                    search(find,script)
                    i = len(script)
        else:
            script.append(line)

if __name__ == "__main__":
    choose = input(f"{Menu()}\n[#] > ")
    if choose.lower() == "c":
        clear()
        print("""
                <---*---*---[ Code.py ]---*---*--->
                """)
        edit()
    elif choose.lower() == "r":
        clear()
        try:
            import code
            code.main()
        except Exception as e:
            print(e)
    elif choose.lower() == "e":
        exit()
    elif choose == "" or len(choose) * " " == choose:
        print("[!] invalid input")
    elif choose.lower() == "h":
        clear()
        Help()
        clear()