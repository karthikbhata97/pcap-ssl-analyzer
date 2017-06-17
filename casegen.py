with open('handshake.txt', 'r') as f:
    for line in f:
        err = line.split('(')[0]
        # err_val = line.split('(')[1].split(')')[0]
        # print('case ' + err_val + ':\n\tcout<<"' + err + '"<<endl;\n\t' + err + '(body);\n\tbreak;')
        print('void ' + err + '(const u_char *body)\n{\nreturn;\n}\n')
