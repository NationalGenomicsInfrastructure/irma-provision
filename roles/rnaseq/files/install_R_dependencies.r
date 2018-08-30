#For edgeR_heatmap_MDS.r
source("http://bioconductor.org/biocLite.R")
biocLite("limma", suppressUpdates=TRUE)
biocLite("edgeR", suppressUpdates=TRUE)

install.packages("data.table", dependencies=TRUE, repos='http://cloud.r-project.org/')
install.packages("gplots", dependencies=TRUE, repos='http://cloud.r-project.org/')

#For dupRadar.r
biocLite("dupRadar", suppressUpdates=TRUE)

install.packages("parallel", dependencies=TRUE, repos='http://cloud.r-project.org/')
