copy-headers() {
    PROJECT=${1-sssd}
    CONTAINER=${2-client}

    OUTDIR="$MY_WORKSPACE/_includes/$PROJECT"
    INDIR=`sudo podman mount $CONTAINER`

    echo "Container $CONTAINER mounted at $INDIR"
    echo "Copying header files to $OUTDIR"

    mkdir -p $OUTDIR
    mkdir -p $OUTDIR/gcc-include
    mkdir -p $OUTDIR/system-include

    pushd $OUTDIR
    sudo cp -r $INDIR/usr/lib/gcc/x86_64-redhat-linux/14/include/ gcc-include
    sudo cp -r $INDIR/usr/include/ system-include
    popd

    sudo chown -R $USER:$USER $OUTDIR
}