using ExeScope.Contracts.Events;
using ExeScope.Contracts.Mapping;
using ExeScope.Core.Models;
using ExeScope.Engine.Mapping;
using Xunit;

namespace ExeScope.Tests;

public class ContractsAndMappingTests
{
    [Fact]
    public void ProcessStartedEvent_ContractStoresAndMapsCorrectly()
    {
        var now = DateTime.UtcNow;
        var evt = new ProcessStartedEvent(
            EventId: 101,
            TimestampUtc: now,
            ProcessId: 1234,
            ParentProcessId: 5678,
            ProcessImage: "powershell.exe",
            ParentImage: "cmd.exe",
            ImagePath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine: "powershell.exe -NoProfile -ExecutionPolicy Bypass"
        );

        var envelope = ContractMapper.ToEnvelope(evt);

        Assert.Equal(101, envelope.EventId);
        Assert.Equal("Process", envelope.Category);
        Assert.Equal(1234, envelope.ProcessId);
        Assert.Equal("powershell.exe", envelope.ProcessImage);
        Assert.NotNull(envelope.ProcessStarted);
        Assert.Equal(5678, envelope.ProcessStarted.ParentProcessId);
        Assert.Equal("powershell.exe -NoProfile -ExecutionPolicy Bypass", envelope.ProcessStarted.CommandLine);

        var roundtrip = ContractMapper.FromEnvelopeToProcess(envelope);
        Assert.NotNull(roundtrip);
        Assert.Equal(evt.ProcessId, roundtrip.ProcessId);
        Assert.Equal(evt.ParentProcessId, roundtrip.ParentProcessId);
        Assert.Equal(evt.ProcessImage, roundtrip.ProcessImage);
        Assert.Equal(evt.CommandLine, roundtrip.CommandLine);
    }

    [Fact]
    public void DllInjectedEvent_ContractStoresAndMapsCorrectly()
    {
        var now = DateTime.UtcNow;
        var evt = new DllInjectedEvent(
            EventId: 202,
            TimestampUtc: now,
            SourceProcessId: 444,
            SourceProcessImage: "malware.exe",
            TargetProcessId: 888,
            TargetProcessImage: "explorer.exe",
            InjectedModulePath: @"C:\Temp\payload.dll",
            Technique: "CreateRemoteThread",
            Details: "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread at 0x7FFE0000",
            RemoteThreadStartAddress: 0x7FFE0000
        );

        var envelope = ContractMapper.ToEnvelope(evt);

        Assert.Equal(202, envelope.EventId);
        Assert.Equal("Injection", envelope.Category);
        Assert.Equal(444, envelope.ProcessId);
        Assert.NotNull(envelope.DllInjected);
        Assert.Equal(888, envelope.DllInjected.TargetProcessId);
        Assert.Equal("CreateRemoteThread", envelope.DllInjected.Technique);
        Assert.Equal(0x7FFE0000ul, envelope.DllInjected.RemoteThreadAddress);

        var roundtrip = ContractMapper.FromEnvelopeToInjection(envelope);
        Assert.NotNull(roundtrip);
        Assert.Equal(evt.SourceProcessId, roundtrip.SourceProcessId);
        Assert.Equal(evt.TargetProcessId, roundtrip.TargetProcessId);
        Assert.Equal(evt.Technique, roundtrip.Technique);
        Assert.Equal(evt.RemoteThreadStartAddress, roundtrip.RemoteThreadStartAddress);
    }

    [Fact]
    public void RegistryModifiedEvent_ContractStoresAndMapsCorrectly()
    {
        var now = DateTime.UtcNow;
        var evt = new RegistryModifiedEvent(
            EventId: 303,
            TimestampUtc: now,
            ProcessId: 1000,
            ProcessImage: "trojan.exe",
            Operation: "SetValue",
            KeyPath: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            ValueName: "SecurityUpdate",
            ValueType: "REG_SZ",
            ValueDataSummary: @"C:\Users\User\AppData\malware.exe",
            Result: "SUCCESS"
        );

        var envelope = ContractMapper.ToEnvelope(evt);

        Assert.Equal(303, envelope.EventId);
        Assert.Equal("Registry", envelope.Category);
        Assert.NotNull(envelope.RegistryModified);
        Assert.Equal("SetValue", envelope.RegistryModified.Operation);
        Assert.Equal(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", envelope.RegistryModified.KeyPath);

        var roundtrip = ContractMapper.FromEnvelopeToRegistry(envelope);
        Assert.NotNull(roundtrip);
        Assert.Equal(evt.KeyPath, roundtrip.KeyPath);
        Assert.Equal(evt.ValueName, roundtrip.ValueName);
        Assert.Equal(evt.ValueDataSummary, roundtrip.ValueDataSummary);
    }

    [Fact]
    public void NetworkConnectionEvent_ContractStoresAndMapsCorrectly()
    {
        var now = DateTime.UtcNow;
        var evt = new NetworkConnectionEvent(
            EventId: 404,
            TimestampUtc: now,
            ProcessId: 1000,
            ProcessImage: "trojan.exe",
            Protocol: "TCP",
            Direction: "Outbound",
            LocalEndpoint: "192.168.1.50:49210",
            RemoteEndpoint: "198.51.100.22:443",
            BytesTransferred: 65536,
            DnsQuery: "c2.malicious-domain.com",
            DnsResponse: "198.51.100.22",
            CorrelationMethod: "EtwExactPid",
            Confidence: "High",
            SecurityNotes: "C2 Beaconing Detected"
        );

        var envelope = ContractMapper.ToEnvelope(evt);

        Assert.Equal(404, envelope.EventId);
        Assert.Equal("Network", envelope.Category);
        Assert.NotNull(envelope.NetworkConnection);
        Assert.Equal("TCP", envelope.NetworkConnection.Protocol);
        Assert.Equal("198.51.100.22:443", envelope.NetworkConnection.RemoteEndpoint);
        Assert.Equal(65536, envelope.NetworkConnection.BytesTransferred);

        var roundtrip = ContractMapper.FromEnvelopeToNetwork(envelope);
        Assert.NotNull(roundtrip);
        Assert.Equal(evt.RemoteEndpoint, roundtrip.RemoteEndpoint);
        Assert.Equal(evt.BytesTransferred, roundtrip.BytesTransferred);
        Assert.Equal(evt.DnsQuery, roundtrip.DnsQuery);
    }

    [Fact]
    public void DomainContractMapper_ConvertsEngineEventsToEnvelopes()
    {
        var domainInjection = new InjectionEvent
        {
            EventId = 505,
            TimestampUtc = DateTime.UtcNow,
            SourceProcessId = 111,
            SourceProcessImage = "dropper.exe",
            TargetProcessId = 222,
            TargetProcessImage = "svchost.exe",
            Technique = InjectionTechnique.DllInjection,
            Details = "Hook injection into svchost",
            RemoteThreadStartAddress = null
        };

        var envelope = DomainContractMapper.ToGrpcEnvelope(domainInjection);

        Assert.Equal(505, envelope.EventId);
        Assert.Equal("Injection", envelope.Category);
        Assert.Equal(111, envelope.ProcessId);
        Assert.NotNull(envelope.DllInjected);
        Assert.Equal(222, envelope.DllInjected.TargetProcessId);
        Assert.Equal("DllInjection", envelope.DllInjected.Technique);
    }
}
