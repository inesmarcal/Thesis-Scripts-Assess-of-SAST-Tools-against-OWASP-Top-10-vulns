import pandas as pd, math, re
import itertools
import copy


def main():
    LATEX = open("LATEX_INDV_COMB2_COMB3.txt", "w")

    tool_dic = {"Semgrep":"A", "Snyk":"B", "Fortify":"C", "Spotbugs":"D", "Kiuwan":"E", "Synopsys":"F", "Horusec":"G"}
    tool_dic_reverse = {"A":"Semgrep", "B":"Snyk", "C":"Fortify", "D":"Spotbugs", "E":"Kiuwan", "F":"Synopsys", "G":"Horusec"}
    scenarios_indx = ["Business Critical", "Heightened Critical", "Best Effort", "Minimum Effort"]
    files = {"Ind": "\\caption{Ranking of Tools by scenario}\n\\label{tab: Ranking of Tools by scenario}\n", 
             "Comb2": "\\caption{Ranking of Combination of 2 Tools by scenario}\n\\label{tab: Ranking of Combination of 2 Tools by scenario}\n", 
             "Comb3": "\\caption{Ranking of Combination of 3 Tools by scenario}\n\\label{tab: Ranking of Combination of 3 Tools by scenario}\n"}

    xl = pd.read_excel('Comb2_Comb3_Ind.xlsx', sheet_name=None)

    for f in files.keys():
        LATEX.write("\\textbf{Results obtained in " + f + "}\\newline\n\n")
        scenarios = {"Business Critical": [], "Heightened Critical": [], "Best Effort": [], "Minimum Effort": []}
        scenario_indx = 0

        for index, row in xl[f].iterrows():
            r = []
            for column, value in row.items():
                r.append(str(value).replace('\n', ' ').replace('\r', ''))

            if r[0] == "nan":
                scenario_indx += 1
            elif r[0] != "Tool":
                tools = r[0].replace("'", "").replace(" ", "").split(",")
                r[0] = tool_dic[tools[0]] + (", " + tool_dic[tools[1]] if len(tools) > 1 else "") + (", " + tool_dic[tools[2]] if len(tools) > 2 else "")

                scenarios[scenarios_indx[scenario_indx]].append(r) 
            else:
                pass

        if f == "Ind":
            #BUSINESS CRITICAL SCENARIO
            LATEX.write("\\begin{longtable}{|wc{1.5in} | *{4}{wc{0.4in}|} wc{0.9in}| wc{0.6in}|}\n")
            LATEX.write("\\hline\n")
            LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{5}{|c|}{Business Critical Scenario} & Metric & Tiebreaker\\\\\n")
            LATEX.write("\\hline\n")
            LATEX.write("\\rowcolor{lightgray}\\centering Combinations of Tools & TP & FP & TN & FN & Recall & Precison\\\\\n")
            LATEX.write("\\hline\n")
            for k in scenarios["Business Critical"]:
                LATEX.write(tool_dic_reverse[k[0]] + " & " + k[3] + " & " + k[4] + " & " + k[5] + " & " + k[6] + " & " + str(round(float(k[8])*100, 2)) + "\\% & " + str(round(float(k[13])*100, 2)) + "\\% \\\\\n")
                LATEX.write("\\hline\n")

            LATEX.write("\\caption{Performance ranking of tools in Business Critical Scenario}\n")
            LATEX.write("\\label{tab:Performance ranking of tools in Business Critical Scenario}\n")  
            LATEX.write("\\end{longtable}\n")
            LATEX.write("\n")
            LATEX.write("\n")

            #HEIGHTENED CRITICAL SCENARIO
            LATEX.write("\\begin{longtable}{|wc{1.5in} | *{4}{wc{0.4in}|} wc{0.9in}| wc{0.6in}|}\n")
            LATEX.write("\\hline\n")
            LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{5}{|c|}{Heightened Critical Scenario} & Metric & Tiebreaker\\\\\n")
            LATEX.write("\\hline\n")
            LATEX.write("\\rowcolor{lightgray}\\centering Combinations of Tools & TP & FP & TN & FN & Rec*Infor & Recall\\\\\n")
            LATEX.write("\\hline\n")
            for k in scenarios["Heightened Critical"]:
                LATEX.write(tool_dic_reverse[k[0]] + " & " + k[3] + " & " + k[4] + " & " + k[5] + " & " + k[6] + " & " + str(round(float(k[9])*100, 2)) + "\\% & " + str(round(float(k[8])*100, 2)) + "\\% \\\\\n")
                LATEX.write("\\hline\n")

            LATEX.write("\\caption{Performance ranking of tools in Heightened Critical Scenario}\n")
            LATEX.write("\\label{tab:Performance ranking of tools in Heightened Critical Scenario}\n")  
            LATEX.write("\\end{longtable}\n")
            LATEX.write("\n")
            LATEX.write("\n")

            #BEST EFFORT SCENARIO
            LATEX.write("\\begin{longtable}{|wc{1.5in} | *{4}{wc{0.4in}|} wc{0.9in}| wc{0.6in}|}\n")
            LATEX.write("\\hline\n")
            LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{5}{|c|}{Best Effort Scenario} & Metric & Tiebreaker\\\\\n")
            LATEX.write("\\hline\n")
            LATEX.write("\\rowcolor{lightgray}\\centering Combinations of Tools & TP & FP & TN & FN & F-measure & Recall\\\\\n")
            LATEX.write("\\hline\n")
            for k in scenarios["Best Effort"]:
                LATEX.write(tool_dic_reverse[k[0]] + " & " + k[3] + " & " + k[4] + " & " + k[5] + " & " + k[6] + " & " + str(round(float(k[10])*100, 2)) + "\\% & " + str(round(float(k[8])*100, 2)) + "\\% \\\\\n")
                LATEX.write("\\hline\n")

            LATEX.write("\\caption{Performance ranking of tools in Best Effort Scenario}\n")
            LATEX.write("\\label{tab:Performance ranking of tools in Best Effort Scenario}\n")  
            LATEX.write("\\end{longtable}\n")
            LATEX.write("\n")
            LATEX.write("\n")

            #MINIMUM EFFORT SCENARIO
            LATEX.write("\\begin{longtable}{|wc{1.5in} | *{4}{wc{0.4in}|} wc{0.9in}| wc{0.6in}|}\n")
            LATEX.write("\\hline\n")
            LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{5}{|c|}{Minimum Effort Scenario} & Metric & Tiebreaker\\\\\n")
            LATEX.write("\\hline\n")
            LATEX.write("\\rowcolor{lightgray}\\centering Combinations of Tools & TP & FP & TN & FN & Markedness & Precision\\\\\n")
            LATEX.write("\\hline\n")
            for k in scenarios["Minimum Effort"]:
                LATEX.write(tool_dic_reverse[k[0]] + " & " + k[3] + " & " + k[4] + " & " + k[5] + " & " + k[6] + " & " + str(round(float(k[12])*100, 2)) + "\\% & " + str(round(float(k[13])*100, 2)) + "\\% \\\\\n")
                LATEX.write("\\hline\n")

            LATEX.write("\\caption{Performance ranking of tools in Minimum Effort Scenario}\n")
            LATEX.write("\\label{tab:Performance ranking of tools in Minimum Effort Scenario}\n")  
            LATEX.write("\\end{longtable}\n")
            LATEX.write("\n")
            LATEX.write("\n")
            
        else:
            LATEX.write("\\begin{scriptsize}\n")
            LATEX.write("\\centering\n")
            LATEX.write("\\begin{longtable}{|>{\\columncolor{lightlightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|} >{\\columncolor{lightlightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|}m{}}\n")
            LATEX.write("\\hline\n")

            LATEX.write("\\rowcolor{lightgray} \\multicolumn{5}{|c|}{Business Critical} & Metric & Tiebreaker & \\multicolumn{5}{c|}{Heightened Critical} & Metric & Tiebreaker\\\\\n")
            LATEX.write("\\hline\n")
            LATEX.write("\\rowcolor{lightlightgray} Comb. & TP & FN & FP & TN & Recall & Precison & Comb. & TP & FN & FP & TN & Rec.*Infor. & Recall\\\\\n")
            LATEX.write("\\hline\n")

            for k, k2 in zip(scenarios["Business Critical"], scenarios["Heightened Critical"]):
                LATEX.write(k[0] + " & " + k[3] + " & " + k[4] + " & " + k[5] + " & " + k[6] + " & " + str(round(float(k[8])*100, 2)) + "\\% & " + str(round(float(k[13])*100, 2)) + "\\% & " + k2[0] + " & " + k2[3] + " & " + k2[4] + " & " + k2[5] + " & " + k2[6] + " & " +  str(round(float(k2[9])*100, 2)) + "\\% & " + str(round(float(k2[8])*100, 2)) + "\\%\\\\\n")
                LATEX.write("\\hline\n")

            LATEX.write("\\rowcolor{lightgray} \\multicolumn{5}{|c|}{Best Effort} & Metric & Tiebreaker & \\multicolumn{5}{c|}{Minimum Effort} & Metric & Tiebreaker\\\\\n")
            LATEX.write("\\hline\n")
            LATEX.write("\\rowcolor{lightlightgray} Comb. & TP & FN & FP & TN & F-measure & Recall & Comb. & TP & FN & FP & TN & Markedness & Precision\\\\\n")
            LATEX.write("\\hline\n")

            for k, k2 in zip(scenarios["Best Effort"], scenarios["Minimum Effort"]):
                LATEX.write(k[0] + " & " + k[3] + " & " + k[4] + " & " + k[5] + " & " + k[6] + " & " + str(round(float(k[10])*100, 2)) + "\\% & " + str(round(float(k[8])*100, 2)) + "\\% & " + k2[0] + " & " + k2[3] + " & " + k2[4] + " & " + k2[5] + " & " + k2[6] + " & " +  str(round(float(k2[12])*100, 2)) + "\\% & " + str(round(float(k2[13])*100, 2)) + "\\%\\\\\n")
                LATEX.write("\\hline\n")
            
            LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{A - Semgrep | B - Snyk | C - Fortify | D - Spotbugs | E - Kiuwan | F - Synospys | G - Horusec}\\\\\n")
            LATEX.write("\\hline\n")
            LATEX.write(files[f])
            LATEX.write("\\end{longtable}\n")
            LATEX.write("\\centering\n")
            LATEX.write("\\end{scriptsize}\n")

            LATEX.write("\n")
            LATEX.write("\n")
            LATEX.write("\n")

if __name__=="__main__":
    main()