# vei-iot-sdk-c
欢迎使用边缘智能设备接入SDK（C语言版），本文档为您介绍SDK编译，以及样例程序的使用。

[边缘智能产品主页](https://www.volcengine.com/product/vei/mainpage)

## 系统要求
当前边缘智能设备接入SDK（C语言版）支持的系统为`macOS`和`Linux`。

## SDK编译
您可以根据需要，选择编译SDK为静态库或动态库。
我们这里假设SDK已经通过`git clone`或压缩包解压到了当前路径下。
```
% tree -L 1
.
├── CMakeLists.txt         // cmake编译脚本
├── LICENSE.txt            // License文件
├── NOTICE.txt             // Notice文件
├── README.md              // 快速使用说明
├── THIRD-PARTY-LICENSES   // 第三方License文件
├── build.sh               // 编译脚本
├── cmake                  // cmake配置
├── examples               // 样例程序源文件
├── libraries              // 第三方库
├── src                    // SDK源文件
└── toolchain_dep.cmake    // 交叉编译配置脚本
```

### 1. 获取依赖库（AWS开源组件库）
由于当前SDK依赖AWS开源组件库，这里需要先获取这些依赖库再进行编译。在当前路径下执行：
```
git submodule update --init --recursive
```

### 2. 编译脚本支持的命令
`build.sh`为主要的编译脚本，可使用`-h`查看支持的参数。
```
% ./build.sh -h
/path/to/vei-iot-sdk-c
Here are supported parameters:
[empty]   build static libraries with examples
-d        build shared libraries with examples
-h        print this help output
-p        bypassing building 3rdparty libraries
-x        cross-compiling with toolchain specified in toolchain_dep.cmake
```
其中，部分参数解释如下：
- 不提供参数: 编译静态库产物和样例程序
- `-d`: 编译动态库产物和样例程序
- `-h`: 列出脚本支持的参数说明
- `-p`: 不编译第三方库；非首次编译指定产物SDK库时，可以跳过对第三方库的重复编译，加快编译进度；
- `-x`: 使用toolchain_dep.cmake文件中指定的交叉编译工具链进行编译

### 3. 编译静态库
```
./build.sh
```
编译静态库的产物在`output_static`文件夹下：
```
output_static
├── example  // 样例程序
├── include  // 头文件
└── lib      // 库文件
```

### 4. 编译动态库
```
./build.sh -d
```
编译动态库的产物在`output_shared`文件夹下：
```
output_shared
├── example  // 样例程序
├── include  // 头文件
└── lib      // 库文件
```

### 5. 交叉编译
这里假设在Linux主机上使用`gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu`这个ARM交叉编译工具来进行ARM64架构的目标库编译。
我们需要编辑`toolchain_dep.cmake`文件，指定交叉编译工具中`gcc`和`g++`编译器的位置，如下所示：
```
# arm64 arch
set(CMAKE_SYSTEM_PROCESSOR arm64)
set(CMAKE_C_COMPILER   /sample/path/to/toolchain/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc )
set(CMAKE_CXX_COMPILER /sample/path/to/toolchain/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-g++ )
```
然后，为`build.sh`编译脚本指定`-x`参数进行编译。
静态库如下：
```
./build.sh -x
```
动态库如下：
```
./build.sh -d -x
```
对应SDK库产物同上述非交叉编译场景文件夹，即`output_static`和`output_shared`。

## 样例程序
在编译SDK库时，样例程序也一同进行了编译，提供在`examples`文件夹下。使用SDK时，并不依赖这些样例程序。在使用样例程序之前，请确保配置了正确的 ProductKey / ProductSecret / DeviceName / DeviceSecret 等，具体可参考边缘智能平台中相关产品与设备信息。其中部分样例程序功能如下：
- demo_temp_humid: 模拟测试场景，温度和湿度属性的上报；
- test_tm_event: 事件上报；
- test_tm_property: 属性上报；
- test_tm_property_set: 属性设置；
- test_tm_service: 服务调用；
- test_tm_custom_topic: 自定义topic；

## 许可证
[Apache-2.0 License](LICENSE).