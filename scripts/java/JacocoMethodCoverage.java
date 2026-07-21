import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jacoco.core.analysis.Analyzer;
import org.jacoco.core.analysis.CoverageBuilder;
import org.jacoco.core.analysis.IClassCoverage;
import org.jacoco.core.analysis.IMethodCoverage;
import org.jacoco.core.tools.ExecFileLoader;

/** Emits covered methods from JaCoCo execution data without analyzer code reuse. */
public final class JacocoMethodCoverage {
  private JacocoMethodCoverage() {}

  private static void collectAncestors(
      String name, Map<String, IClassCoverage> classes, Set<String> result) {
    IClassCoverage clazz = classes.get(name);
    if (clazz == null) {
      return;
    }
    String superName = clazz.getSuperName();
    if (superName != null && result.add(superName)) {
      collectAncestors(superName, classes, result);
    }
    for (String interfaceName : clazz.getInterfaceNames()) {
      if (result.add(interfaceName)) {
        collectAncestors(interfaceName, classes, result);
      }
    }
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      throw new IllegalArgumentException(
          "usage: JacocoMethodCoverage <jacoco.exec> <classfiles>...");
    }
    ExecFileLoader loader = new ExecFileLoader();
    loader.load(new File(args[0]));
    CoverageBuilder coverage = new CoverageBuilder();
    Analyzer analyzer = new Analyzer(loader.getExecutionDataStore(), coverage);
    for (int index = 1; index < args.length; index++) {
      analyzer.analyzeAll(new File(args[index]));
    }

    Map<String, IClassCoverage> classes = new HashMap<>();
    for (IClassCoverage clazz : coverage.getClasses()) {
      classes.put(clazz.getName(), clazz);
    }
    List<String> rows = new ArrayList<>();
    for (IClassCoverage clazz : coverage.getClasses()) {
      Set<String> ancestors = new HashSet<>();
      collectAncestors(clazz.getName(), classes, ancestors);
      List<String> orderedAncestors = new ArrayList<>(ancestors);
      Collections.sort(orderedAncestors);
      for (IMethodCoverage method : clazz.getMethods()) {
        int covered = method.getInstructionCounter().getCoveredCount();
        int total = method.getInstructionCounter().getTotalCount();
        if (covered > 0) {
          rows.add(
              clazz.getName() + "\t" + method.getName() + "\t"
                  + method.getDesc() + "\t" + covered + "\t" + total + "\t"
                  + String.join(";", orderedAncestors));
        }
      }
    }
    Collections.sort(rows);
    for (String row : rows) {
      System.out.println(row);
    }
  }
}
