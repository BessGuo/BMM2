#add include $ using namespace to each txt file
#cp to here and compile

Code_path="/home/newdisk/gyx/SCIS/dataset/POJ/poj_data/code/"
Binary_path="../binary/"
Max_Program_ID=104   #104
Script_path=$(cd "$(dirname "$0")"; pwd)
Log_file=${Script_path}"/log/compile_log"

for ((i=4;i<=Max_Program_ID;i++))
do
{
    echo "Program ${i} compile log:" >> $Log_file
    cd ${Binary_path}
    if [ ! -d $i ];then
        mkdir $i
    fi
    cd $i
    Path=${Code_path}${i}"/"
    for file in `ls $Path`
    do
        id=`echo ${file} | awk -F. '{print $1}'`
        echo ${file}
        echo "> Program ${i} code ${id} compile" >> $Log_file
        cat ${Script_path}/lib_list_cpp ${Path}${file} > ${id}".cpp"
        g++ -o ${id} ${id}".cpp" 2>> $Log_file
        if [ ! -f ${id} ];then
            cat ${Script_path}/lib_list ${Path}${file} > ${id}".c"
            gcc -o ${id} ${id}".c" 2>> $Log_file
        fi
    done
    #rename 's/txt/cpp/' *.txt
    cd ${Script_path}
}&
done
wait


