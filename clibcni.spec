%global _version 2.0.7
%global _release 1
Name:      clibcni
Version:   %{_version}
Release:   %{_release}
Summary:   CNI - the Container Network Interface
Group:     System Environment/Libraries
License:   Mulan PSL v2
URL:       clibcni
Source0:   %{name}-2.0.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}

BuildRequires: gcc
BuildRequires: cmake
BuildRequires: libisula-devel yajl-devel gtest-devel

Requires:      libisula

%ifarch x86_64 aarch64
Provides:       lib%{name}.so()(64bit)
%endif

%description
CNI (Container Network Interface), a Cloud Native Computing Foundation project,
consists of a specification and libraries for writing plugins to configure
network interfaces in Linux containers, along with a number of supported
plugins. CNI concerns itself only with network connectivity of containers and
removing allocated resources when the container is deleted. Because of this
focus, CNI has a wide range of support and the specification is simple to implement.

%package devel
Summary: Huawei CNI C Library
Group:   Libraries
ExclusiveArch:  x86_64 aarch64
Requires:       %{name} = %{version}-%{release}

%description devel
the %{name}-libs package contains libraries for running %{name} applications.


%prep
%setup -c -n %{name}-%{version}

%build
mkdir -p build
cd build
%cmake -DDEBUG=ON -DENABLE_UT=ON -DLIB_INSTALL_DIR=%{_libdir} ../
%make_build

pushd tests
ctest -V
popd

%install
rm -rf %{buildroot}
cd build
install -d $RPM_BUILD_ROOT/%{_libdir}
install -m 0644 ./src/libclibcni.so        %{buildroot}/%{_libdir}/libclibcni.so
chmod +x %{buildroot}/%{_libdir}/libclibcni.so

install -d $RPM_BUILD_ROOT/%{_libdir}/pkgconfig
install -m 0644 ./conf/clibcni.pc      %{buildroot}/%{_libdir}/pkgconfig/clibcni.pc

install -d $RPM_BUILD_ROOT/%{_includedir}/clibcni
install -m 0644 ../src/api.h           %{buildroot}/%{_includedir}/clibcni/api.h
install -m 0644 ../src/types/types.h   %{buildroot}/%{_includedir}/clibcni/types.h
install -m 0644 ../src/version/version.h %{buildroot}/%{_includedir}/clibcni/version.h


find %{buildroot} -type f -name '*.la' -exec rm -f {} ';'
find %{buildroot} -name '*.a' -exec rm -f {} ';'
find %{buildroot} -name '*.cmake' -exec rm -f {} ';'

%clean
rm -rf %{buildroot}

%pre

%post   -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/lib%{name}.so*

%files devel
%defattr(-,root,root,-)
%{_includedir}/%{name}/*.h
%{_libdir}/pkgconfig/%{name}.pc


%changelog
* Mon Oct 11 2021 wujing <wujing50@huawei.com> - 2.0.5
- Type:sync
- ID:NA
- SUG:NA
- DESC: upgrade version to 2.0.5

* Mon Aug 03 2020 openEuler Buildteam <buildteam@openeuler.org> - 2.0.2-20200803.124729.git693f2545
- Type:enhancement
- ID:NA
- SUG:NA
- DESC: add debug packages
