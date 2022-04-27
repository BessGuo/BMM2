Script_path=$(cd "$(dirname "$0")"; pwd)
Binary_path="/home/newdisk/gyx/SCIS/dataset/POJ/poj_data/binaryAllType/"
Dataset_path="/home/newdisk/gyx/SCIS/dataset/POJ/poj_data/modelInput/"


target="poj"

if [ "$target" == "poj" ];then

    echo ">Build Target == poj"

    Compile_tag="O3" #O3_ffast remember change:id=${file::-7}
    Compiler="gcc"
    Max_Program_ID=104        

    Program_path=${Binary_path}
    Result_path=${Dataset_path}"/"${Compiler}"/"${Compile_tag}"/"

    for ((i=1;i<=Max_Program_ID;i++))
    do
    {
        if [ ! -d ${Result_path}${i} ];then
            mkdir ${Result_path}${i}
        fi
        #for file in `ls *-${Compiler}-${Compile_tag}`
        for file in `ls ${Program_path}${i}/*-${Compiler}-${Compile_tag}`
        do
        {
            if [ "$Compiler" == "llvm" ];then
                id=${file::-8}
            else
                id=${file::-13} #if is Ox_ffast, change to 13 '-gcc-Ox_ffast'; if is Ox,change to 7
            fi
            
            id=`echo $id | awk -F "/" '{print $7}'`
            timeout 20m python dfg_build.py --target_program="poj"  --output=${Output_path} --comp_t=${Compiler} --opti_t=${Compile_tag} --pro_class=$i --filename=${id}
            timeout 20m python cg_build.py --target_program="poj" --output=${Output_path} --comp_t=${Compiler} --opti_t=${Compile_tag} --pro_class=$i --filename=${id}
            timeout 20m python cfg_build.py --target_program="poj" --output=${Output_path} --comp_t=${Compiler} --opti_t=${Compile_tag} --pro_class=$i --filename=${id}
                        
            #python ass_dic.py --target_program="poj" --input=${Input_type} --output=${Output_path} --comp_t=${Compiler} --opti_t=${Compile_tag} --pro_class=$i --filename=${id}
        }&
        done
        wait
    }
    done
fi

if [ "$target" == "spec" ];then

    echo "target==spec"

    Compile_tag_list=("o3" "o2")
    Compiler_list=("gcc" "llvm")
    Arch_list=("x86")  #("arm" "x86")
    Time=$(date "+%Y-%m-%d_%H_%M_%S")
    Log_file_part="./Log/"${Time}

    for ((i=0;i<1;i++))
    do
    {
        Arch=${Arch_list[$i]}
        for ((j=0;j<1;j++)) #2
        do
        {
            Compiler=${Compiler_list[$j]}
            for ((k=0;k<1;k++)) #2
            do
            {
                Compile_tag=${Compile_tag_list[$k]}
                
		        #for file in  "526.blender_r" "510.parest_r" "502.gcc_r" "511.povray_r" "538.imagick_r" "541.leela_r" "505.mcf_r" "508.namd_r" "544.nab_r" "557.xz_r" # "523.xalancbmk_r" "520.omnetpp_r" 
                for file in  "557.xz_r" "508.namd_r" "505.mcf_r" "541.leela_r" "544.nab_r" "511.povray_r" "520.omnetpp_r" "538.imagick_r" "526.blender_r" "502.gcc_r" "510.parest_r" "523.xalancbmk_r"
                #for file in "557.xz_r" 
                do
                {
                    log_file=${file}"_"${Compiler}"_"${Compile_tag}" "${Log_file_part}
                    python3 dfg_build.py --target_program="spec" --output="../../trainData/spec_ori_data" --arch_t=${Arch}  --comp_t=${Compiler} --opti_t=${Compile_tag}  --filename=${file}  #>>${log_file} 2>>${log_file}
                } #&
                done
                #wait
            }&
            done
            wait
        } #&
        done
        #wait
    }&
    done
    wait

    echo "Finish."
fi


