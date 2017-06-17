with open('alert.txt', 'r') as f:
    for line in f:
        err = line.split('(')[0]
        err_val = line.split('(')[1].split(')')[0]
        print('case ' + err_val + ':\n      cout<<"' + err + '"<<endl;\n      break;')
