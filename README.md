# Thesis_Scripts-Assess_of_DAST_Tools_against_OWASP_Top_10_vulns
- [x] Finished
- [ ] Add more modularity to the code to ease the process of analysis with other tools and web applications
- [ ] Make the code more readable, i.e. less complex

## Index
- [Description](#description)
- [Technologies used](#technologies-used)
- [To run this project](#to-run-this-project)
- [Notes important to read](#notes-important-to-read)
- [Authors](#authors)

## Description
The scripts provided in this repository were developed in the context of the thesis "Evaluation of Static Analysis Tools in Detecting OWASP Top 10 vulnerabilities". @University of Coimbra, Master of Cybersecurity. <br>
Since the main objective is to evaluate the selected tools regarding their performance, these scripts accomplish multiple tasks:
- Classification of the output obtained by the tools
  - Web applications: Excel file
  - Test case sets (Juliet Test Suite and OWASP Benchmark): sets of test cases in which the expected output for each file is already stated.
- Counting the number of TPs, FNs, FPs and TNs that each tool achieved
- Generation of Excel files that simplify the calculation and the management of the metrics results for combinations of 2 tools with weights.
- Generation of Latex tables, from the gathered results, to facilitate the process of adding them to the written thesis.

Some Excel files are also provided and are used as templates for several purposes:
- checkmark list of the test cases used as workload (template/regular_apps/GLOBAL_RESULTS.xlsx)
- checkmark list of FP test cases gathered from the output of the tools, e.g. cases where there is no vulnerability and the tools detect it like this (template/regular_apps/GLOBAL_FP.xlsx)
- Auxiliary file to collect the data obtained by the scripts and to support the calculation of the metrics (recall, informedness*recall, f-measure, markedness) for single tools, combinations of 2 and 3 (without weights) (template/METRICS.xlsx)
- file to be filled with the rankings of individual tools, combinations of 2 and 3 without weights, which will be used to generate the corresponding latex tables.  (template/regular_apps/top_vuln_scenario/Comb2_Comb3_Ind.xlsx)
- file to fill with the rankings of combinations of 2 tools using weights, which will be used to generate the respective latex tables (template/regular_apps/top_comb2_comb3/Comb2_Vuln.xlsx)

#### Main Languages:
![](https://img.shields.io/badge/Python-333333?style=flat&logo=python&logoColor=4F74DA)

## Technologies used:
1. Python
    - [Version 3.9](https://www.python.org/downloads/release/python-390/)
2. Libraries:<br>
    - [Pandas](https://pandas.pydata.org)
    - [Itertools](https://docs.python.org/3/library/itertools.html)
    - [Xml.dom](https://docs.python.org/3/library/xml.dom.html)


## To run this project:
There will be 3 execution flows for these scripts. Two of them correspond to the 2 test case sets Juliet Test Suite and OWASP Benchmark. The other is the main execution flow, which collects and analyzes all the results produced by the tools, in particular those of the combinations of 2 and 3 tools without weights and combinations of 2 tools with weights, and then generates Latex tables. So the scripts are executed as follows:
1. owasp_benchmark folder <br>
   Gather the expect cookies vulnerable and non-vulnerable instances:
   * First unzip BenchmarkJava.zip on the [your-disk]:[name-path]\owasp_benchmark\expect_test_cases_list path
   * Run the following command:
     ```shellscript
     [your-disk]:[name-path]\owasp_benchmark\expect_test_cases_list> python expectedresults_cookies.py
     ```

     This will generate 2 files, result_vuln_cookie.txt and result_nonvuln_cookie.txt, corresponding to the existing vulnerable and non-vulnerable instances of the OWASP benchmark test case, respectively, which will be used later to classify the results obtained by the tools regarding the "Bad Programming of Cookies" vulnerability.

   The main script is executed next:
   * The next step is to run the main code of this flow of execution. The first time this script is run, it should be commented from line 1266 to 1330 because this part deals with combinations of 2 tools using weights, and at this point the file WEIGHTS.txt doesn't exist (it will be generated later in the main script from the regular_apps folder). Later on, these lines will be uncommented when certain files are generated.
     ```shellscript
     [your-disk]:[name-path]\owasp_benchmark> python verify_results_juliettestsuite.py
     ```

     This will generate an output of all results achieved by the tools against the OWASP benchmark for all types of analysis performed. It will also create the following files:
     - kiuwan\KIUWAN_FILE.txt - a file from a separate analysis to the Kiuwan tool
     - latex\LATEX_OWASPBENCHMARK.txt - the latex code for the results obtained by the tools in this platform (TPs, FNs, FPs and TNs)
     - weight_combinations_2_results\FINAL_VULNING_2.txt - a file to be opened as an Excel and that will be used to calculate the metrics for the combinations of 2 tools using weights per vulnerability
     - VULNING_BENCHMARK.txt - a file to be used on the regular_apps\combinations.py script to generate the weights for each tool regarding each vulnerability and scenario
     
2. juliet_test_suite folder <br>
   Gather the expect instances (since there isn't an expect list of existent issues as for OWASP Benchmark):
   * First unzip Juliet.zip on the [your-disk]:[name-path]\juliet_test_suite\expect_test_cases_list path
   * Compile the project:
     ```shellscript
     [your-disk]:[name-path]\juliet_test_suite\expect_test_cases_list> sh script.sh
     ``` 
   * Run the following command:
     ```shellscript
     [your-disk]:[name-path]\juliet_test_suite\expect_test_cases_list> python expect_results_juliettestsuite.py
     ```

     This will generate a file called expected.txt which will correspond to the existent vulnerable and non-vulnerable instances of the Juliet Test Suite testcase, that will be used later to classify the results obtained by the tools.

   The main script will be executed nextly:
   * The next step is to run the main code of this flow of execution. The first time this script is run you should comment it from line 1226 to 1323, as this part regards with combinations of 2 tools using weights and at this point the file WEIGHTS.txt doesn't exist (will be generated later in the main script from regular_apps folder). Later you will be able to uncomment these lines when certain files will be generated.
     ```shellscript
     [your-disk]:[name-path]\owasp_benchmark> python verify_results_benchmarkowasp.py
     ```

     This will generate an output of all the results achieved by the tools in the Juliet Test Suite about all the types of analysis executed. It will also generate the following files:
     - kiuwan\KIUWAN_FILE.txt - a file from a separate analysis to the tool Kiuwan
     - latex\LATEX_JULIET.txt - the latex code for the results obtained by the tools in this platform (TPs, FNs, FPs and TNs)
     - weight_combinations_2_results\FINAL_VULNING_2.txt - a file to be opened as an Excel and that will be used to calculate the metrics for the combinations of 2 tools using weights per vulnerability
     - VULNING_JULIET.txt - a file to be used on the regular_apps\combinations.py script to generate the weights for each tool regarding each vulnerability and scenario
     
3. regular_apps <br>
   Here we start by running the main script:
   * Here is where most of the tasks will be done, namely classification of the tools in the majority of the applications (by outputing it), calculus of the weights, generation of a big part of the latex tables.
     ```shellscript
     [your-disk]:[name-path]\regular_apps> python combinations.py
     ```

     This will generate an output of all the results achieved by the tools in the applications that aren't benchmark platforms about all the type of analysis executed. Will also generate the following files:
     - kiuwan\KIUWAN_FILE.txt and kiuwan\KIUWAN_FILE_FP.txt - files from a separate analysis to the tool Kiuwan
     - latex_of_other_applications\LATEX.txt - the latex code for the results obtained by the tools in these applications (TPs, FNs, FPs and TNs)
     - results_weights_2\FINAL_VULNING_2.txt - a file to be open as an excel and that will be used to calculate the metrics for the combinations of 2 tools using weights per vulnerability
     - initial_vulning\VULNING.txt - a file to be used to generate the weights for each tool regarding each vulnerability and scenario
     - weights_table\WEIGHTS.txt - the file that contains all the weights of all tools regarding the scenario and vulnerability analysed.

   For the generationg of the rest of latex tables:
   * To generate latex tables for individual tools, combinations of 2 and 3 tools without weights:
     ```shellscript
     [your-disk]:[name-path]\regular_apps> python top_comb_2_comb_3\top_comb.py
     ```
   * To generate latex tables for combinations of 2 tools using weights:
     ```shellscript
     [your-disk]:[name-path]\regular_apps> python top_vuln_scenario\top_vuln.py
     ```
   * To generate latex tables for the weights:
     ```shellscript
     [your-disk]:[name-path]\regular_apps> python weights_table\weights_table.py
     ```

## Notes important to read
- For more information about the thesis linked to these scripts read it on [ADD LINK WHEN AVAILABLE]
- The folder #template will contain a template of how the folders should be organized, for that unzip the zip in it called template.zip
- The folder resources contains the exact folders used through this analysis (which have the same structure as the template provided)
- The file WEIGHTS.txt created by regular_apps\combinations.py script should be copied, after generated, to the folders owasp_benchmark\weight_combinations_2_results and juliet_test_suite\weight_combinations_2_results. With this you should uncomment the lines previously commented to make the analysis of combinations of 2 tools using weights for the OWASP Benchmark and Juliet Test Suite.
- The examples of the template files for OWASP Benchmark and Juliet Test Suite are someway "hardcoded" to the tools used, so if you need to use other tools you can follow the same logic as demonstrated, but adapt this code for the platforms you would use. If you only use regular web applications like Webgoat or Juice Shop you can just use the excel provided, the code easy adaptable. Even tho, one the future steps will be the generalization of this code.



## Authors:
- [Inês Marçal](https://github.com/inesmarcal)
