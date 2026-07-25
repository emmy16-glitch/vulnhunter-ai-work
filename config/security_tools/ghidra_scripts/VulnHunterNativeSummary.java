// Collect a bounded, machine-readable summary after headless Ghidra analysis.
// The script prints one VULNHUNTER_JSON line for the parent worker to parse.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.util.ArrayList;
import java.util.List;

public class VulnHunterNativeSummary extends GhidraScript {
    private static final int MAX_NAMES = 64;

    @Override
    public void run() throws Exception {
        int functionCount = 0;
        int externalFunctionCount = 0;
        int jniExportCount = 0;
        List<String> jniExports = new ArrayList<>();

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            functionCount++;
            if (function.isExternal()) {
                externalFunctionCount++;
            }
            String name = function.getName();
            if ("JNI_OnLoad".equals(name) || name.startsWith("Java_")) {
                jniExportCount++;
                if (jniExports.size() < MAX_NAMES) {
                    jniExports.add(name);
                }
            }
        }

        StringBuilder json = new StringBuilder();
        json.append("{");
        appendString(json, "program", currentProgram.getName());
        json.append(",");
        appendString(json, "executable_format", currentProgram.getExecutableFormat());
        json.append(",");
        appendString(json, "language", currentProgram.getLanguageID().toString());
        json.append(",");
        appendString(json, "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        json.append(",\"function_count\":").append(functionCount);
        json.append(",\"external_function_count\":").append(externalFunctionCount);
        json.append(",\"jni_export_count\":").append(jniExportCount);
        json.append(",\"jni_exports\":[");
        for (int index = 0; index < jniExports.size(); index++) {
            if (index > 0) {
                json.append(",");
            }
            json.append("\"").append(escape(jniExports.get(index))).append("\"");
        }
        json.append("]}");
        println("VULNHUNTER_JSON:" + json);
    }

    private static void appendString(StringBuilder target, String key, String value) {
        target.append("\"").append(escape(key)).append("\":\"")
              .append(escape(value == null ? "" : value)).append("\"");
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
    }
}
