// https://gitlab.com/antora/antora/-/issues/132#note_712132072
'use strict'


module.exports.register = (pipeline, { config }) => {

    pipeline.on('contentAggregated', ({ contentAggregate }) => {
        contentAggregate.forEach(aggregate => {
            if (aggregate.name === "" && aggregate.displayVersion === 5.6) {
                aggregate.name = "ROOT";
                aggregate.version = "5.6.0-RC1"
                aggregate.startPage = "ROOT:index.adoc"
                aggregate.displayVersion = `${aggregate.version}`
                delete aggregate.prerelease
            }
            if (aggregate.version === "5.6.1" &&
                    aggregate.prerelease == "-SNAPSHOT") {
                aggregate.version = "5.6.1"
                aggregate.displayVersion = `${aggregate.version}`
                delete aggregate.prerelease
            }
        })
    })
}

function out(args) {
    console.log(JSON.stringify(args, no_data, 2));
}


function no_data(key, value) {
    if (key == "data" || key == "files") {
        return value ? "__data__" : value;
    }
    return value;
}
