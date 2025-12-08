#!/usr/bin/env bash
set -e

############################################
# OpenCV 4.10.0 + FFmpeg + GStreamer (NO CUDA)
# Ubuntu 24.04 (VMware-friendly)
############################################

OPENCV_VERSION="4.10.0"
INSTALL_PREFIX="/usr/local"
LOG_FILE="$HOME/opencv_build.log"

echo "=========================================="
echo "Installing dependencies..."
echo "=========================================="

sudo apt update
sudo apt install -y \
    build-essential cmake git pkg-config \
    libgtk-3-dev \
    python3-dev python3-numpy \
    libjpeg-dev libpng-dev libtiff-dev \
    libopenexr-dev \
    libtbb-dev \
    libdc1394-dev \
    \
    ffmpeg \
    libavcodec-dev libavformat-dev libavutil-dev \
    libswscale-dev libavfilter-dev \
    \
    libgstreamer1.0-dev \
    libgstreamer-plugins-base1.0-dev \
    gstreamer1.0-tools \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-ugly \
    gstreamer1.0-libav \
    \
    v4l-utils

echo "=========================================="
echo "Cloning OpenCV $OPENCV_VERSION..."
echo "=========================================="

rm -rf opencv opencv_contrib
git clone -b $OPENCV_VERSION https://github.com/opencv/opencv.git
git clone -b $OPENCV_VERSION https://github.com/opencv/opencv_contrib.git

mkdir -p opencv/build
cd opencv/build

echo "=========================================="
echo "Configuring CMake..."
echo "=========================================="

cmake \
  -D CMAKE_BUILD_TYPE=Release \
  -D CMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
  -D OPENCV_GENERATE_PKGCONFIG=ON \
  -D OPENCV_EXTRA_MODULES_PATH=../../opencv_contrib/modules \
  -D WITH_FFMPEG=ON \
  -D WITH_GSTREAMER=ON \
  -D WITH_V4L=ON \
  -D WITH_EIGEN=ON \
  -D WITH_TBB=ON \
  -D WITH_OPENGL=ON \
  -D WITH_OPENCL=ON \
  -D WITH_CUDA=OFF \
  -D WITH_CUDNN=OFF \
  .. | tee -a $LOG_FILE

echo "=========================================="
echo "Building OpenCV... (this may take a while)"
echo "Logging to $LOG_FILE"
echo "=========================================="

make -j"$(nproc)" 2>&1 | tee -a $LOG_FILE

echo "=========================================="
echo "Installing OpenCV..."
echo "=========================================="
sudo make install 2>&1 | tee -a $LOG_FILE
sudo ldconfig

echo "=========================================="
echo "DONE!"
echo "Build log: $LOG_FILE"
echo ""
echo "Verify OpenCV with:"
echo "python3 - <<EOF"
echo "import cv2"
echo "print(cv2.getBuildInformation())"
echo "EOF"


