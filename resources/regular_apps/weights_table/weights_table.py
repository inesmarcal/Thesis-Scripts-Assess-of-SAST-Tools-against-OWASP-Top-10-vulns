import pandas as pd, math, re
import itertools
import copy


def main():
    LATEX = open("LATEX_WEIGHTS.txt", "w")

    vulns = {"BYPASS AUTHORIZATION": "Bypassing Authorization",
             "INSUFFICIENT SESSION EXPIRATION": "Insufficient Session Expiration",
             "PATH TRANSVERSAL": "Path Traversal",
             "CSRF": "Cross-Site Request Forgery",
             "INSECURE ALGORITHM": "Use of Old/Insecure algorithms",
             "WEAK HASH": "Deprecated Hash Functions",
             "WEAK RANDOM": "Use of Weak PRNG",
             "SEED HARDCODED": "Seeds Hard Coded in PRNG",
             "OS COMMAND INJECTION": "OS Command Injection",
             "SQL INJECTION": "SQL Injection",
             "LDAP INJECTION": "LDAP Injection",
             "XSS": "Cross-Site Scripting",
             "XPATH": "XPath Injection",
             "HTTP SPLITTING": "HTTP Response Splitting",
             "IMPROPER ERROR HANDLING": "Improper Error Handling",
             "TRUST BOUNDARY": "Trust Boundary Violation",
             "METHOD TAMPERING": "Method Tampering",
             "XXE": "XML External Entities",
             "BAD PROGRAMMING COOKIES": "Bad Programming of Cookies",
             "HARDCODED CONSTANTS": "Insecure Use of Hard Coded Constants",
             "OUTDATED COMPONENTS": "Vulnerable Third-Party Components",
             "BYPASS AUTHENTICATION": "Bypassing Authentication",
             "HARDCODED CREDENTIALS": "Hard Coded Passwords",
             "INSECURE DESERIALIZATION": "Insecure Deserialization",
             "OUTPUT NEUTRALIZATION OF LOGS": "Improper Output Neutralization for Logs",
             "SSRF": "Server-Side Request Forgery"
            }

    vuln_list = list(vulns.keys())

    lines = open("WEIGHTS.txt", "r").readlines()
    num = 1

    LATEX.write("\\begin{scriptsize}\n")
    LATEX.write("\\centering\n")
    LATEX.write("\\begin{longtable}{|>{\\columncolor{lightlightgray}}wc{0.6in} | *{4}{wc{0.85cm}|}  >{\\columncolor{lightlightgray}}wc{0.6in} | *{4}{wc{0.85cm}|} m{}}\n")
    LATEX.write("\\hline\n")

    for l in lines:
        lin = l[:-1]
        #print(lin)

        if lin in vuln_list:
            #print(vulns[lin])
            if num == 1:
                index_vuln = vuln_list.index(lin)
                LATEX.write("\\rowcolor{lightlightgray} Vulnerability & \\multicolumn{4}{c|}{" + vulns[vuln_list[index_vuln]] + "} & Vulnerability & \\multicolumn{5}{c|}{" + vulns[vuln_list[index_vuln+1]] + "}\\\\\n")
                LATEX.write("\\hline\n")
                LATEX.write("\\rowcolor{lightlightgray} Tool & 1 & 2 & 3 & 4 & Tool & 1 & 2 & 3 & 4\\\\\n")
                LATEX.write("\\hline\n")

            #print(num)
            num = 1 + (0 if num%2==0 else 1)
        else:
            if num == 1:
                if len(l[:-1].split(" ")) != 1:
                    index_line = lines.index(l)
                    #LATEX.write(
                    LATEX.write(" & ".join((lines[index_line-10][:-1]+" "+lines[index_line][:-1]).split(" "))+"\\\\\n\\hline\n")

    LATEX.write("\\rowcolor{lightlightgray} \\multicolumn{10}{|c|}{1 - Business Critical | 2 - Heightened Critical | 3 - Best Effort | 4 - Minimum Effort}\\\\\n")
    LATEX.write("\\hline\n")
    LATEX.write("\\caption{Weights of each tool for each scenario regarding all the vulnerabilities}\n")
    LATEX.write("\\label{tab:Weights of each tool for each scenario regarding all the vulnerabilities}\n")
    LATEX.write("\\end{longtable}\n")
    LATEX.write("\\end{scriptsize}\n")



if __name__=="__main__":
    main()