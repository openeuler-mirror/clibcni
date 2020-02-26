%global _version 1.0.8
%global _release 20191225.122403.git49093ba7
Name:      clibcni
Version:   %{_version}
Release:   %{_release}
Summary:   CNI - the Container Network Interface
Group:     System Environment/Libraries
License:   Mulan PSL v1
URL:       clibcni
Source0:   %{name}-1.0.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}

BuildRequires: gcc
BuildRequires: cmake
BuildRequires: yajl yajl-devel
BuildRequires: python3

Requires:      yajl

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

%global debug_package %{nil}

%prep
%setup -c -n %{name}-%{version}

%build
mkdir -p build
cd build
%cmake -DDEBUG=OFF -DLIB_INSTALL_DIR=%{_libdir} ../
%make_build

%install
rm -rf %{buildroot}
cd build
install -d $RPM_BUILD_ROOT/%{_libdir}
install -m 0644 ./src/libclibcni.so        %{buildroot}/%{_libdir}/libclibcni.so

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
