
import os, re

def main():
    file = open("expected.txt", "w+")
    base_dir = "Juliet\\src\\testcases"
    dir_list=os.listdir(base_dir)
    good_regex = "(void|String) good([0-9]+|G2B[0-9]*|B2G[0-9]*)(Source|Sink)*\\("
    bad_regex = "(void|String) bad\\("

    for dr in dir_list:
        file_list = os.listdir(base_dir + "\\" + dr)
        dic_files = {}
        
        for fl in file_list:
            finish = 0
            after_fl, after_line = "", 0
            if fl[-5:] == ".java":
                key = re.split("(|[a-z]|_bad|_goodG2B|_base).java", fl)[0]
                #print(parts)
                if key in dic_files:
                    dic_files[key].append(fl)
                else:
                    dic_files[key] = [fl]


        base_filename = base_dir + "\\" + dr + "\\"
        for k, v in dic_files.items():
            #print(k)
            #print(v)
            string = ""
            quant = 0

            string += "," + k + "," + str(dr) + "," + "\n"
            for vn in v:
                if re.search("_bad.java", vn):
                    quant += 1
                    string += "\t" + str(vn) + "," + str(dr) + ",TRUE,\n"
                elif re.search("_goodG2B.java", vn):
                    quant += 1
                    string += "\t" + str(vn) + "," + str(dr) + ",FALSE,\n"
                else:
                    f = open(base_filename + vn, "r")
                    lines = f.readlines()

                    for i in range(len(lines)):
                        if re.search(good_regex, lines[i]):
                            quant += 1
                            string += "\t" + str(vn) + "," + str(dr) + ",NEUTRAL," + str(i+1) + ",\n"
                            finish = 1
                            break
            
            file.write(str(quant) + string)
                

if __name__=="__main__":
    main()