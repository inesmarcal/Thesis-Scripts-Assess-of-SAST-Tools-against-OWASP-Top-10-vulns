import pandas as pd, math, re
import itertools
import copy


def main():
    LATEX = open("LATEX_VULNS.txt", "w")

    vulns = {"BYPASS AUTHORIZATION": "Bypassing Authorization",
             "SESSION EXPIRATION": "Insufficient Session Expiration",
             "PATH TRANSVERSAL": "Path Traversal",
             "CSRF": "Cross-Site Request Forgery",
             "INSECURE ALGORITHM": "Use of Old/Insecure algorithms",
             "WEAK HASH": "Deprecated Hash Functions",
             "WEAK RANDOM": "Use of Weak PRNG",
             "SAMESEED": "Seeds Hard Coded in PRNG",
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

    tool_dic = {"Semgrep":"A", "Snyk":"B", "Fortify":"C", "Spotbugs":"D", "Kiuwan":"E", "Synopsys":"F", "Horusec":"G"}

    categories = {"A1": [["BYPASS AUTHORIZATION", "SESSION EXPIRATION", "PATH TRANSVERSAL", "CSRF"], "A1: Broken Access Control"],
                  "A2": [["INSECURE ALGORITHM", "WEAK HASH", "WEAK RANDOM", "SAMESEED"], "A2: Cryptographic Failures"],
                  "A3": [["OS COMMAND INJECTION", "SQL INJECTION", "LDAP INJECTION", "XSS", "XPATH", "HTTP SPLITTING"], "A3: Injection"],
                  "A4": [["IMPROPER ERROR HANDLING", "TRUST BOUNDARY", "METHOD TAMPERING"], "A4: Insecure Design"],
                  "A5": [["XXE", "BAD PROGRAMMING COOKIES", "HARDCODED CONSTANTS"], "A5: Security Misconfiguration"],
                  "A6": [["OUTDATED COMPONENTS"], "A6: Vulnerable and Outdated Components"], 
                  "A7": [["BYPASS AUTHENTICATION", "HARDCODED CREDENTIALS"], "A7: Identification and Authentication Failures"],
                  "A8": [["INSECURE DESERIALIZATION"], "A8: Software and Data Integrity Failures"],
                  "A9": [["OUTPUT NEUTRALIZATION OF LOGS"], "A9: Security Logging and Monitoring Failures"], 
                  "A10": [["SSRF"], "A10: Server-Side Request Forgery"]
                 } 

    scenarios_indx = ["Business Critical", "Heightened Critical", "Best Effort", "Minimum Effort"]

    xl = pd.read_excel('Comb2_Vuln.xlsx', sheet_name=None)

    for cat in categories.keys():
        LATEX.write("\\textbf{\\Large Results obtained in " + categories[cat][1] + "}\\newline\n\n")

        scenarios = {"Business Critical": [], "Heightened Critical": [], "Best Effort": [], "Minimum Effort": []}
        vuln_atual = ""
        vuln_indx = 0

        for index, row in xl[cat].iterrows():
            r = []
            for column, value in row.items():
                r.append(str(value).replace('\n', ' ').replace('\r', ''))
            
            if r[0] == "nan":
                continue
            elif r[0] in categories[cat][0]:
                if vuln_atual == r[0]:
                    vuln_indx += 1
                else:
                    vuln_atual = r[0]
                    vuln_indx = 0
            elif r[0] != "Tool":
                tools = r[0][1:-1].replace("'", "").replace(" ", "").split(",")
                r[0] = tool_dic[tools[0]] + ", " + tool_dic[tools[1]]

                scenarios[scenarios_indx[vuln_indx]].append(r+[vuln_atual]) 
            else:
                pass
            #print(r)
        
        LATEX.write("\\begin{scriptsize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\begin{longtable}{|>{\\columncolor{lightlightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|} >{\\columncolor{lightlightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|}m{}}\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{" + categories[cat][1] + "}\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray} \\multicolumn{5}{|c|}{Business Critical} & Metric & Tiebreaker & \\multicolumn{5}{c|}{Heightened Critical} & Metric & Tiebreaker\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightlightgray} Comb. & TP & FN & FP & TN & Recall & Precison & Comb. & TP & FN & FP & TN & Rec.*Infor. & Recall\\\\\n")
        LATEX.write("\\hline\n")
        
        vuln_latex = ""
        for k, k2 in zip(scenarios["Business Critical"], scenarios["Heightened Critical"]):
            if k[-1] != vuln_latex:
                vuln_latex = k[-1]
                LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{" + vulns[vuln_latex] + "}\\\\\n")
                LATEX.write("\\hline\n")
            
            LATEX.write(k[0] + " & " + k[9] + " & " + k[13] + " & " + k[17] + " & " + k[21] + " & " + (str(round(float(k[1])*100, 2)) if k[1] != "nan" else "0.00") + "\\% & " + (str(round(float(k[5])*100, 2)) if k[5] != "nan" else "0.00") + "\\% & " + k2[0] + " & " + k2[10] + " & " + k2[14] + " & " + k2[18] + " & " + k2[22] + " & " +  (str(round(float(k2[2])*100, 2)) if k2[2] != "nan" else "0.00") + "\\% & " + (str(round(float(k2[6])*100, 2)) if k2[6] != "nan" else "0.00")  + "\\%\\\\\n")
            LATEX.write("\\hline\n")

        LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{A - Semgrep | B - Snyk | C - Fortify | D - Spotbugs | E - Kiuwan | F - Synospys | G - Horusec}\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\caption{Ranking of combinations of 2 SAST tools regarding their performance in category " + categories[cat][1] + " - Business and Heightened Critical Scenarios}\n")
        LATEX.write("\\label{tab:" + categories[cat][1] + " - Business and Heightened Critical Scenarios}\n")
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\end{scriptsize}\n")

        LATEX.write("\n")
        LATEX.write("\n")
        LATEX.write("\n")

        LATEX.write("\\begin{scriptsize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\begin{longtable}{|>{\\columncolor{lightlightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|} >{\\columncolor{lightlightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|}m{}}\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{" + categories[cat][1] + "}\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray} \\multicolumn{5}{|c|}{Best Effort} & Metric & Tiebreaker & \\multicolumn{5}{c|}{Minimum Effort} & Metric & Tiebreaker\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightlightgray} Comb. & TP & FN & FP & TN & F-measure & Recall & Comb. & TP & FN & FP & TN & Markedness & Precision\\\\\n")
        LATEX.write("\\hline\n")
        
        vuln_latex = ""
        for k, k2 in zip(scenarios["Best Effort"], scenarios["Minimum Effort"]):
            if k[-1] != vuln_latex:
                vuln_latex = k[-1]
                LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{" + vulns[vuln_latex] + "}\\\\\n")
                LATEX.write("\\hline\n")
            
            LATEX.write(k[0] + " & " + k[11] + " & " + k[15] + " & " + k[19] + " & " + k[23] + " & " + (str(round(float(k[3])*100, 2)) if k[3] != "nan" else "0.00") + "\\% & " + (str(round(float(k[7])*100, 2)) if k[7] != "nan" else "0.00") + "\\% & " + k2[0] + " & " + k2[12] + " & " + k2[16] + " & " + k2[20] + " & " + k2[24] + " & " +  (str(round(float(k2[4])*100, 2)) if k2[4] != "nan" else "0.00") + "\\% & " + (str(round(float(k2[8])*100, 2)) if k2[8] != "nan" else "0.00") + "\\%\\\\\n")
            LATEX.write("\\hline\n")

        LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{A - Semgrep | B - Snyk | C - Fortify | D - Spotbugs | E - Kiuwan | F - Synospys | G - Horusec}\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\caption{Ranking of combinations of 2 SAST tools regarding their performance in category " + categories[cat][1] + " - Best and Minimum Effort Scenarios}\n")
        LATEX.write("\\label{tab:" + categories[cat][1] + " - Best and Minimum Effort scenarios}\n")
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\end{scriptsize}\n")

        LATEX.write("\n")
        LATEX.write("\n")
        LATEX.write("\n")

        #print(scenarios["Business Critical"])
        #print(scenarios["Heightened Critical"])
        #print(scenarios["Best Effort"])
        #print(scenarios["Minimum Effort"])




if __name__=="__main__":
    main()