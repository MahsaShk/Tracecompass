package org.eclipse.tracecompass.incubator.anomaly.detection.core.controlFlow;





import java.util.Collections;
import java.util.Iterator;


import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.tracecompass.internal.analysis.os.linux.core.kernel.StateValues;

import org.eclipse.tracecompass.statesystem.core.ITmfStateSystem;
import org.eclipse.tracecompass.statesystem.core.exceptions.StateSystemDisposedException;
import org.eclipse.tracecompass.statesystem.core.exceptions.TimeRangeException;
import org.eclipse.tracecompass.statesystem.core.interval.ITmfStateInterval;
import org.eclipse.tracecompass.tmf.core.analysis.IAnalysisModule;
import org.eclipse.tracecompass.tmf.core.analysis.TmfAbstractAnalysisModule;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfAnalysisException;
import org.eclipse.tracecompass.tmf.core.trace.ITmfContext;
import org.eclipse.tracecompass.analysis.os.linux.core.event.aspect.LinuxTidAspect;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import java.util.List;
import java.util.LinkedList;

import java.io.FileWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;

import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;
import org.eclipse.tracecompass.analysis.graph.core.base.TmfGraph;
import org.eclipse.tracecompass.analysis.graph.core.building.TmfGraphBuilderModule;
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelAnalysisModule;






public class controlFlowExtraction extends TmfAbstractAnalysisModule {


    static @Nullable ITmfStateSystem myStateSystem = null;
    TmfGraphBuilderModule cpaModule = null;
    TmfGraph graph = null;
    @Override
    protected boolean executeAnalysis(@NonNull IProgressMonitor monitor) throws TmfAnalysisException {
        //Read trace
        ITmfTrace trace2 = getTrace();
        @NonNull
        ITmfTrace trace = trace2;
        String outpDir = "./";
        System.out.println(outpDir);


        KernelAnalysisModule an = TmfTraceUtils.getAnalysisModuleOfClass(trace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
        checkNotNull(an);

        boolean flag = false;
        Iterable<IAnalysisModule> dependentAnalyses = getDependentAnalyses(); 
        for (IAnalysisModule module : dependentAnalyses) {
            System.out.println(module.getClass());
            if (!(module instanceof KernelAnalysisModule)) {
                System.out.println(false);

            }
            System.out.println(flag);
            flag = module.waitForCompletion();
        }

        if (flag == true && an!=null) {
            myStateSystem = an.getStateSystem();
            checkNotNull(myStateSystem);
            writeFeatures(myStateSystem, outpDir);

        }
        if (myStateSystem!=null)
         {
            List<Integer> quarks = myStateSystem.getQuarks("CPUs","*");
            System.out.println(quarks);
           // System.out.println("duration(milisecond):"+(myStateSystem.getCurrentEndTime())/1000000);//-myStateSystem.getStartTime())/1000000);
        }

        System.out.println("finished");



        return false;
    }



    @Override
    protected void canceling() {
        // TODO Auto-generated method stub

    }

    @Override
    protected Iterable<IAnalysisModule> getDependentAnalyses() {
        ITmfTrace trace = getTrace();

        cpaModule = TmfTraceUtils.getAnalysisModuleOfClass(trace, TmfGraphBuilderModule.class, CPA_ID);
        checkNotNull(cpaModule);
        return Collections.singleton(cpaModule);
    }



    private static <T> @NonNull T checkNotNull(@Nullable T obj) {
        if (obj == null) {
            throw new NullPointerException();
        }
        return obj;
    }


    private static void writeFeatures(ITmfStateSystem stateSystem, String outpDir) {
        List<Integer> syscalls_quarks = stateSystem.getQuarks("Threads", "*", "System_call");
        List<Integer> exec_name_quarks = stateSystem.getQuarks("Threads", "*", "Exec_name");
        Integer[] integers = new Integer[1];
        integers[0] = 1033;
        List<Integer> threads_quarks = stateSystem.getQuarks("Threads","*");

        checkNotNull(syscalls_quarks);
        long start = stateSystem.getStartTime();
        long end = stateSystem.getCurrentEndTime();
        long duration = (end -start);
        System.out.println("duration"+duration);

        Iterable<ITmfStateInterval> iterable=null;
        Iterable<ITmfStateInterval> proc_name_iterable=null;
        Iterable<ITmfStateInterval> threads_iterable=null;
        try {
            syscalls_iterable = stateSystem.query2D(syscalls_quarks, start, end);
            proc_name_iterable = stateSystem.query2D(proc_name_quarks, start, end);
            threads_iterable = stateSystem.query2D(threads_quarks, start, end);

        } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }

        /*
        for (ITmfStateInterval interval : proc_name_iterable) {//iterate over all intervals and collect metrics
            Integer quark = interval.getAttribute();
            Object tmp = interval.getValue();
            if (tmp!=null) {
                if (tmp.toString().toLowerCase().contains("mysql".toLowerCase()))
                    {
                    System.out.println(interval);
                    System.out.println(quark);
                    System.out.println(interval.getValue());
                    System.out.println(interval.getStateValue());
                    }
            }

        }
        */

       /* for (ITmfStateInterval interval : syscalls_iterable) {//iterate over all intervals and collect metrics
            Integer quark = interval.getAttribute();
            System.out.println(interval);
            System.out.println(quark);
        }*/

        // reads intervals of "mysql" thread and sort it while reading. The quark of MySql is 1033
        LinkedList<ITmfStateInterval> ll_sortedIntervals = new LinkedList<>();
        Long nxtstarttime;
        if (threads_iterable != null)
        {
            for (ITmfStateInterval interval : threads_iterable) {//iterate over all intervals and collect metrics
               Integer quark = interval.getAttribute();
               if (quark ==1033) { // find based on proc_name =="mysql"
                   if (ll_sortedIntervals.size() == 0) {
                    ll_sortedIntervals.add(0,interval);

                   }
                   else {
                       Iterator<ITmfStateInterval> iter_itvl1 = ll_sortedIntervals.iterator();
                       Integer index_ll = 0;
                       while(iter_itvl1.hasNext()){
                           nxtstarttime = iter_itvl1.next().getStartTime();

                           if (nxtstarttime > interval.getStartTime()) {
                               ll_sortedIntervals.add(index_ll, interval);
                               break;
                           }
                           index_ll ++;
                       }

                       if (index_ll == ll_sortedIntervals.size()) { // interval time is bigger than current list element
                           ll_sortedIntervals.add(index_ll,interval);
                       }


                   }

               }

            }
        }

        System.out.println(" The intervals are sorted");
        System.out.println("ll_sortedIntervals size:" + ll_sortedIntervals.size());

        // Write the sorted interval in a file
        Iterator<ITmfStateInterval> iter_itvl1 = ll_sortedIntervals.iterator();
        FileWriter fileItvl;
        String FileNameItvl = "intvl_sorted.txt";
        try { // to check for fileItvl
            fileItvl = new FileWriter(outpDir+FileNameItvl);

            while(iter_itvl1.hasNext()){
                fileItvl.write(iter_itvl1.next().toString()+"\n");
            }
            fileItvl.close();
        }catch(IOException e) {
            e.printStackTrace();
        }




    }

}





