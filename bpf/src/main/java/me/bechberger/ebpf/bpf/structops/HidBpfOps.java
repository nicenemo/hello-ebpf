package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.HidDefinitions;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code hid_bpf_ops}. Implement to intercept and
 * modify HID (Human Interface Device) reports before they reach userspace.
 *
 * <p>{@link #hidDeviceEvent} returns bytes of report modified, or a negative
 * errno on failure.
 *
 * <p>{@link #hidId()} is the HID device identifier the ops match on
 * (0 = wildcard, or a specific product/vendor id). Data field in the kernel
 * struct.
 */
@StructOps("hid_bpf_ops")
public interface HidBpfOps {

    default int hidDeviceEvent(Ptr<HidDefinitions.hid_bpf_ctx> hctx,
                               int type, @Unsigned long source)          { return 0; }
    default int hidRdescFixup(Ptr<HidDefinitions.hid_bpf_ctx> hctx)       { return 0; }
    default int hidHwRequest(Ptr<HidDefinitions.hid_bpf_ctx> hctx,
                             @Unsigned int reportnum,
                             int rtype, int reqtype,
                             @Unsigned long source)                       { return 0; }

    /**
     * Called whenever {@code hid_hw_output_report()} is emitted for the device (for example the LED output report
     * of the keyboard driver). Return 0 to let the report through, any other value stops it. Needs a kernel whose
     * {@code struct hid_bpf_ops} has the {@code hid_hw_output_report} member (7.x).
     */
    default int hidHwOutputReport(Ptr<HidDefinitions.hid_bpf_ctx> hctx,
                                  @Unsigned long source)                  { return 0; }

    /** HID device identifier (0 = any). */
    default int hidId() { return 0; }
}
