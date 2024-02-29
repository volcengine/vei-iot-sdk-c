#!/bin/bash

#
# Copyright 2022-2024 Beijing Volcano Engine Technology Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set +x
set -e

ROOT=$(pwd)
echo $ROOT;

# 指定编译产物为动态库或静态库
SHARED_LIBS=off
# 是否跳过编译第三方库
BYPASS_3RDPARTY_LIBRARIES=off
# 交叉编译开关
CROSS_COMPILE=off
CMAKE_TOOLCHAIN_FILE=$ROOT/toolchain_dep.cmake

HELP_OUTPUT="Here are supported parameters:
[empty]   build static libraries with examples
-d        build shared libraries with examples
-h        print this help output
-p        bypassing building 3rdparty libraries
-x        cross-compiling with toolchain specified in toolchain_dep.cmake
"

while getopts ":hdpx" opt
do
  case $opt in
    h)
      echo "$HELP_OUTPUT"
      exit 0;;
    d)
      SHARED_LIBS=on;;
    p)
      BYPASS_3RDPARTY_LIBRARIES=on;;
    x)
      CROSS_COMPILE=on;;
    ?)
      echo "Invalid parameter."
      echo "$HELP_OUTPUT"
      exit 1;;
  esac
done

if [[ "$SHARED_LIBS" == "on" ]]; then
  echo Building shared libs
else
  echo Building static libs
fi

# 编译第三方依赖库
INSTALL_PATH=$ROOT/libraries/3rdparty_build
echo $INSTALL_PATH;

cd $ROOT/libraries/3rdparty
for lib in "aws-lc" "s2n-tls" "aws-c-common" "aws-c-cal" "aws-c-io" "aws-c-compression" "aws-c-http" "aws-c-mqtt";do
  if [[ "$BYPASS_3RDPARTY_LIBRARIES" == "on" ]]; then
    continue
  fi
  echo $lib

  pwd

  if [[ "$lib" == "s2n-tls" ]]; then
    cd $lib
    echo "codebuild s2n_setup_env"
    S2N_LIBCRYPTO=openssl-1.1.1 BUILD_S2N=true TESTS=integration GCC_VERSION=9
    source codebuild/bin/s2n_setup_env.sh
    cd ..
  fi

  rm -rf $lib/build
  mkdir -p $lib/build
  cd $lib/build

  if [[ "$CROSS_COMPILE" == "on" ]]; then
    cmake .. -DBUILD_TESTING=off -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DCMAKE_PREFIX_PATH=$INSTALL_PATH -DBUILD_SHARED_LIBS=$SHARED_LIBS -DCMAKE_TOOLCHAIN_FILE=$CMAKE_TOOLCHAIN_FILE
  else
    cmake .. -DBUILD_TESTING=off -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DCMAKE_PREFIX_PATH=$INSTALL_PATH -DBUILD_SHARED_LIBS=$SHARED_LIBS
  fi

  cd ..
  cd ..
  pwd
  cmake --build $lib/build --target install
done

# 编译核心库
cd $ROOT
rm -rf $ROOT/build
mkdir -p build
cd build
WITH_EXAMPLES=on
if [[ "$CROSS_COMPILE" == "on" ]]; then
  cmake .. -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DCMAKE_PREFIX_PATH=$INSTALL_PATH -DBUILD_EXAMPLES=$WITH_EXAMPLES -DBUILD_SHARED_LIBS=$SHARED_LIBS -DCMAKE_TOOLCHAIN_FILE=$CMAKE_TOOLCHAIN_FILE
else
  cmake .. -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DCMAKE_PREFIX_PATH=$INSTALL_PATH -DBUILD_EXAMPLES=$WITH_EXAMPLES -DBUILD_SHARED_LIBS=$SHARED_LIBS
fi

if [[ "$SHARED_LIBS" == "on" ]]; then
  make iot_sdk_shared
  OUTPUT=output_shared
else
  make iot_sdk_static
  OUTPUT=output_static
fi

cd $ROOT

# 整理输出产物
lib_dir=$ROOT/$OUTPUT/lib
echo $lib_dir
include_dir=$ROOT/$OUTPUT/include
echo $include_dir
example_dir=$ROOT/$OUTPUT/examples
echo $example_dir
if [ -d $OUTPUT ]
then
    $(rm -r $OUTPUT)
fi

$(mkdir -p $lib_dir)
$(mkdir -p $include_dir)
$(mkdir -p $example_dir/iot)
$(mkdir -p $example_dir/use)

if [[ "$SHARED_LIBS" == "on" ]]; then
  if [[ "$OSTYPE" =~ ^darwin ]]; then
    cp $ROOT/libraries/3rdparty_build/lib/*.dylib $lib_dir
    cp $ROOT/build/src/arenal/*.dylib $lib_dir
  elif [[ "$OSTYPE" =~ ^linux ]]; then
    cp $ROOT/libraries/3rdparty_build/lib/*.so* $lib_dir
    cp $ROOT/build/src/arenal/*.so $lib_dir
  fi
else
  cp $ROOT/libraries/3rdparty_build/lib/*.a $lib_dir
  cp $ROOT/build/src/arenal/*.a $lib_dir
  cd $lib_dir
  if [[ "$OSTYPE" =~ ^darwin ]]; then
      libtool -static -o libbyteiot.a *.a
  elif [[ "$OSTYPE" =~ ^linux ]]; then
      echo "create libbyteiot.a
addlib libaws-c-cal.a
addlib libaws-c-compression.a
addlib libaws-c-io.a
addlib libcrypto.a
addlib libssl.a
addlib libaws-c-common.a
addlib libaws-c-http.a
addlib libaws-c-mqtt.a
addlib libs2n.a
addlib libiot_sdk_static.a

save
end" > newLib.mri
      ar -M <./newLib.mri
      rm -rf newLib.mri
  fi
  rm `ls *.a | grep -v libbyteiot.a`
fi

# 拷贝头文件
cp -r $ROOT/examples/include/* $include_dir

# 准备编译样例程序
cp -r $lib_dir $ROOT/examples/
cd $ROOT/build/examples/
for example in "demo_temp_humid" "test_tm_event" "test_tm_property" "test_tm_property_set" "test_tm_service";do
  make $example
  if [[ "$example" == "demo_temp_humid" ]]; then
    cp $ROOT/build/examples/$example $example_dir/use/
  else
    cp $ROOT/build/examples/$example $example_dir/iot/
  fi
done

echo "#######################################"
echo "Build complete."
echo "#######################################"
