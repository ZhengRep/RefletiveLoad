# RefletiveLoad

## 介绍

本项目主要实现了反射式注入，反射式注入是注入方式的一种。该种方式主要思想是通过在DLL中实现加载DLL函数，实现自我加载，与远程线程相比的优点是，注射器只需启用加载器，让加载器在目标进程中自动加载本身DLL，并调用DLL的DllMain入口函数（Entry Point），减少了和目标进程的通信开销（降低被检测出的风险:grin:)

注入（Inject）就是在目标进程的地址空间插入自己需要执行的代码。而注入方式又以DLL注入最为常见，其注入方法可分为两大类：静态注入，就是PE文件在加载成Image时系统会根据其导入表加载对应的DLL；动态注入，PE中自行调用加载方法（LoadLibrary）。

动态注入以远程线程、APC注入、修改EIP……

## ReflectiveLoad实现

实现分为注射器和加载器，注射器根据用户输入的PID，读取本地DLL文件，拷贝到目标进程空间，并调用DLL中的加载器，成功加载后通过一段ShellCode，调用DllMain。

### 项目文件结构

```shell
  '    |-- Inject', //注射器
  '    |   |-- Inject.cpp',
  '    |   |-- Inject.h',
  '    |   |-- Inject.vcxproj',
  '    |   |-- Inject.vcxproj.filters',
  '    |   |-- Inject.vcxproj.user',
  '    |   |-- main.cpp', //调用加载器
  '    |-- Reflective_dll', //加载器
  '    |   |-- dllmain.cpp', //Dll Entry Point
  '    |   |-- framework.h',
  '    |   |-- pch.cpp',
  '    |   |-- pch.h',
  '    |   |-- ReflectiveLoader.cpp',
  '    |   |-- ReflectiveLoader.h',
  '    |   |-- Reflective_dll.vcxproj',
  '    |   |-- Reflective_dll.vcxproj.filters',
  '    |   |-- Reflective_dll.vcxproj.user',
```



### 项目实现细节

**注射器的实现**



**加载器的实现**



**ShellCode的实现**



## Debug

1. 

